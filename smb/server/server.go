package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/sonroyaalmerol/go-smb-server/smb/auth"
	"github.com/sonroyaalmerol/go-smb-server/smb/encryption"
	"github.com/sonroyaalmerol/go-smb-server/smb/ntlmssp"
	"github.com/sonroyaalmerol/go-smb-server/smb/signing"
	"github.com/sonroyaalmerol/go-smb-server/smb/transport"
	"github.com/sonroyaalmerol/go-smb-server/smb/vfs"
	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

const (
	defaultMaxTransact uint32 = 65536
	defaultMaxRead     uint32 = 1 << 20
	defaultMaxWrite    uint32 = 1 << 20
	defaultMaxCredits  uint32 = 8192

	cleanupCloseTimeout = 5 * time.Second
)

type Server struct {
	addr          string
	authFactory   auth.Factory
	shares        []vfs.Share
	shareByName   map[string]vfs.Share
	dialect       uint16
	locker        vfs.ByteRangeLocker
	maxConcurrent int
	maxTransact   uint32
	maxRead       uint32
	maxWrite      uint32
	maxCredits    uint32
	requireEnc    bool
	log           *slog.Logger
	guid          [16]byte

	mu       sync.Mutex
	listener net.Listener
}

type Option func(*Server)

func WithAddr(addr string) Option { return func(s *Server) { s.addr = addr } }

func WithAuth(f auth.Factory) Option { return func(s *Server) { s.authFactory = f } }

func WithShares(shares ...vfs.Share) Option {
	return func(s *Server) { s.shares = append(s.shares, shares...) }
}

func WithLogger(l *slog.Logger) Option { return func(s *Server) { s.log = l } }

func WithMaxCredits(n uint32) Option { return func(s *Server) { s.maxCredits = n } }

func WithEncryptionRequired() Option { return func(s *Server) { s.requireEnc = true } }

// WithLocker records byte-range locks in l instead of the server's own
// in-memory table, so locks taken over SMB can share a table with locks taken
// over other protocols.
func WithLocker(l vfs.ByteRangeLocker) Option { return func(s *Server) { s.locker = l } }

// WithMaxConcurrentRequests bounds how many reads and writes a single
// connection handles at once. 0 selects the default; 1 handles every request
// in turn, as the server did before.
func WithMaxConcurrentRequests(n int) Option {
	return func(s *Server) { s.maxConcurrent = n }
}

func WithDialect(d uint16) Option { return func(s *Server) { s.dialect = d } }

func New(opts ...Option) (*Server, error) {
	s := &Server{
		addr:          ":445",
		dialect:       wire.DialectSMB302,
		locker:        newMemLocker(),
		maxConcurrent: defaultMaxConcurrent,
		maxTransact:   defaultMaxTransact,
		maxRead:       defaultMaxRead,
		maxWrite:      defaultMaxWrite,
		maxCredits:    defaultMaxCredits,
		log:           slog.Default(),
	}
	for _, opt := range opts {
		opt(s)
	}
	if len(s.shares) == 0 {
		return nil, errors.New("server: at least one share is required")
	}
	if s.authFactory == nil {
		s.authFactory = auth.AlwaysAllowFactory()
	}
	s.shareByName = make(map[string]vfs.Share, len(s.shares))
	for _, sh := range s.shares {
		s.shareByName[sh.Name()] = sh
	}

	if _, ok := s.shareByName["IPC$"]; !ok {
		shareNames := make([][2]string, len(s.shares)+1)
		shareNames[0] = [2]string{"IPC$", "Remote IPC"}
		for i, sh := range s.shares {
			shareNames[i+1] = [2]string{sh.Name(), ""}
		}
		pb := vfs.NewPipeBackend()
		pb.Register("srvsvc", vfs.SrvsvcHandler(shareNames))
		ipcShare := vfs.NewDiskShare("IPC$", pb)
		s.shares = append(s.shares, ipcShare)
		s.shareByName["IPC$"] = ipcShare
	}

	if _, err := rand.Read(s.guid[:]); err != nil {
		return nil, fmt.Errorf("server: generate guid: %w", err)
	}
	return s, nil
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("server: listen %s: %w", s.addr, err)
	}
	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.listener = nil
		s.mu.Unlock()
		_ = ln.Close()
	}()
	s.log.Info("smb server listening", "addr", ln.Addr().String())

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	var wg sync.WaitGroup
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return nil
			}
			return fmt.Errorf("server: accept: %w", err)
		}
		wg.Go(func() {
			s.serveConn(ctx, c)
		})
	}
}

func (s *Server) Shutdown() error {
	s.mu.Lock()
	ln := s.listener
	s.listener = nil
	s.mu.Unlock()
	if ln != nil {
		return ln.Close()
	}
	return nil
}

type session struct {
	auth           auth.Authenticator
	identity       *auth.Identity
	authenticated  bool
	mu             sync.RWMutex
	trees          map[uint32]*tree
	nextTreeID     uint32
	signer         *signing.Signer
	requireSign    bool
	encryptionKey  []byte
	decryptionKey  []byte
	requireEncrypt bool
	encCCM         *encryption.AESCCM
	decCCM         *encryption.AESCCM
}

type tree struct {
	share   vfs.Share
	mu      sync.RWMutex
	opens   map[[16]byte]*openHandle
	nextID  uint64
	oplocks *oplockTable
}

// open returns an open handle by id.
func (t *tree) open(id [16]byte) (*openHandle, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	oh, ok := t.opens[id]
	return oh, ok
}

// addOpen records a new open handle and returns its id.
func (t *tree) addOpen(oh *openHandle) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.opens[oh.fileId] = oh
}

// removeOpen forgets an open handle.
func (t *tree) removeOpen(id [16]byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.opens, id)
}

// allOpens is a snapshot of the tree's open handles.
func (t *tree) allOpens() []*openHandle {
	t.mu.RLock()
	defer t.mu.RUnlock()
	opens := make([]*openHandle, 0, len(t.opens))
	for _, oh := range t.opens {
		opens = append(opens, oh)
	}
	return opens
}

// nextFileID hands out the next open counter.
func (t *tree) nextFileID() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nextID++
	return t.nextID
}

type openHandle struct {
	h             vfs.Handle
	fileId        [16]byte
	sessionID     uint64
	path          string
	deletePending bool
	enumDone      bool
	enumMu        sync.Mutex

	// Directory enumeration is paged: clients ask repeatedly, sometimes one
	// entry at a time, until the server reports no more files. The entries
	// are captured on the first call so later calls continue where the
	// previous one stopped.
	enumStarted bool
	enumEntries []vfs.FileInfo
	enumIndex   int
}

// request is one message being handled. It embeds the connection, so
// handlers reach shared state as before, but owns the buffer its response is
// built in: that is what lets several requests be handled at once.
type request struct {
	*conn
	out []byte
}

type conn struct {
	srv           *Server
	fc            *transport.FramedConn
	log           *slog.Logger
	sessionsMu    sync.RWMutex
	sessions      map[uint64]*session
	nextSess      uint64
	creditMu      sync.Mutex
	creditBalance uint32

	nextAsync    uint64
	pending      map[uint64]*pendingOp
	pendingByMsg map[uint64]*pendingOp
	pendingMu    sync.Mutex
	outbox       chan []byte
	connDone     chan struct{}
	writerDone   chan struct{}
	// inflight bounds concurrent request handlers, and handlers tracks them
	// so the connection waits for them before closing its open files.
	inflight chan struct{}
	handlers sync.WaitGroup

	preauthHash []byte

	// negDialect and negCaps are what NEGOTIATE actually answered on this
	// connection. FSCTL_VALIDATE_NEGOTIATE_INFO must echo them exactly:
	// clients compare the two and drop the connection when they differ.
	negDialect uint16
	negCaps    uint32
}

func (s *Server) serveConn(ctx context.Context, c net.Conn) {
	defer func() { _ = c.Close() }()
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	sha := sha512.New()
	sha.Write(nil)
	cn := &conn{
		srv:           s,
		fc:            transport.NewFramedConn(c),
		log:           s.log,
		sessions:      make(map[uint64]*session),
		creditBalance: 1,
		pending:       make(map[uint64]*pendingOp),
		pendingByMsg:  make(map[uint64]*pendingOp),
		outbox:        make(chan []byte, 64),
		connDone:      make(chan struct{}),
		writerDone:    make(chan struct{}),
		inflight:      make(chan struct{}, s.concurrentRequests()),
		preauthHash:   sha.Sum(nil),
	}
	defer cn.cleanup()
	go cn.writeLoop()

	for {
		if err := ctx.Err(); err != nil {
			return
		}
		_ = cn.fc.Underlying().SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		msg, err := cn.fc.ReadMessage()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			if !errors.Is(err, net.ErrClosed) {
				cn.log.Debug("read error", "err", err)
			}
			return
		}
		_ = cn.fc.Underlying().SetReadDeadline(time.Time{})

		if isSMB1Negotiate(msg) {
			// Windows opens with an SMB1 multi-protocol negotiate listing
			// "SMB 2.???". Answering with the wildcard dialect makes it
			// retry in SMB2; ignoring it makes the client hang, then reset.
			r := &request{conn: cn}
			r.replyWildcardNegotiate()
			cn.send(r.out)
			continue
		}

		if len(msg) >= 4 && msg[0] == 0xFD {
			dec, dErr := cn.openTransform(msg)
			if dErr != nil {
				cn.log.Debug("decrypt error", "err", dErr)
				return
			}
			msg = dec
		} else if len(msg) >= wire.HeaderSize && msg[0] == wire.SMB2ProtocolId[0] {
			sessID := binary.LittleEndian.Uint64(msg[40:48])
			if sess := cn.getSession(sessID); sess != nil && sess.requireEncrypt {
				cn.log.Debug("plaintext on encrypted session, dropping")
				return
			}
		}

		cmdBefore := uint16(0xFFFF)
		if len(msg) >= wire.HeaderSize {
			cmdBefore = binary.LittleEndian.Uint16(msg[12:14])
		}
		if cmdBefore == wire.CmdNegotiate || cmdBefore == wire.CmdSessionSetup {
			cn.updatePreauth(msg)
		}
		if cn.canHandleConcurrently(msg) {
			// ReadMessage hands back a buffer it reuses, so a request that
			// outlives this loop iteration needs its own copy.
			queued := append([]byte(nil), msg...)
			select {
			case cn.inflight <- struct{}{}:
			case <-connCtx.Done():
				return
			}
			cn.handlers.Add(1)
			go func() {
				defer cn.handlers.Done()
				defer func() { <-cn.inflight }()
				r := &request{conn: cn}
				r.handleMessage(connCtx, queued)
				cn.send(r.out)
			}()
			continue
		}

		r := &request{conn: cn}
		r.handleMessage(connCtx, msg)
		cn.send(r.out)
	}
}

// smb1NegotiateHeader is the start of an SMB1 NEGOTIATE request: the SMB1
// protocol id followed by command 0x72.
var smb1NegotiateHeader = []byte{0xFF, 'S', 'M', 'B', 0x72}

// isSMB1Negotiate reports whether msg is an SMB1 negotiate offering SMB2.
func isSMB1Negotiate(msg []byte) bool {
	return bytes.HasPrefix(msg, smb1NegotiateHeader) && bytes.Contains(msg, []byte("SMB 2."))
}

// replyWildcardNegotiate answers an SMB1 negotiate with an SMB2 negotiate
// response carrying the wildcard dialect, so the client renegotiates in
// SMB2 (MS-SMB2 section 3.3.5.3.1).
func (c *request) replyWildcardNegotiate() {
	hdr := wire.NewHeader(wire.CmdNegotiate)
	hdr.Flags = wire.FlagServerToRedir
	hdr.Credit = 1
	c.out = hdr.Append(c.out)
	resp := wire.NegotiateResponse{
		SecurityMode:    wire.SigningEnabled,
		DialectRevision: wire.DialectWildcard,
		ServerGuid:      c.srv.guid,
		Capabilities:    c.negotiateCapabilities(),
		MaxTransactSize: c.srv.maxTransact,
		MaxReadSize:     c.srv.maxRead,
		MaxWriteSize:    c.srv.maxWrite,
		SecurityBuffer:  ntlmssp.NegTokenInitNTLM(),
	}
	c.out = resp.Append(c.out)
}

// defaultMaxConcurrent is how many reads and writes one connection handles at
// once by default. Requests wait on the object store far more than on the
// gateway, so handling them in turn would leave a client waiting a round trip
// per request.
const defaultMaxConcurrent = 64

// concurrentRequests is the configured bound, with 0 meaning the default.
func (s *Server) concurrentRequests() int {
	if s.maxConcurrent > 0 {
		return s.maxConcurrent
	}
	return defaultMaxConcurrent
}

// canHandleConcurrently reports whether a message can be handled off the read
// loop. Only reads and writes qualify: they use a file handle that already
// exists, while every other request may create or destroy session, tree, or
// handle state, which stays ordered on the read loop. Compound and related
// requests stay there too, because their parts share state.
func (c *conn) canHandleConcurrently(msg []byte) bool {
	if c.srv.concurrentRequests() <= 1 || len(msg) < wire.HeaderSize || msg[0] != wire.SMB2ProtocolId[0] {
		return false
	}
	var hdr wire.Header
	if err := hdr.Parse(msg); err != nil {
		return false
	}
	if hdr.NextCommand != 0 || hdr.Flags&wire.FlagRelatedOps != 0 {
		return false
	}
	if hdr.Command != wire.CmdRead && hdr.Command != wire.CmdWrite {
		return false
	}
	sess := c.getSession(hdr.SessionId)
	return sess != nil && sess.authenticated
}

// writeLoop owns the connection's output: every response is written here, so
// handlers can run in more than one goroutine without interleaving frames.
// A write error closes the connection, which ends the read loop too.
func (c *conn) writeLoop() {
	defer close(c.writerDone)
	for {
		select {
		case resp := <-c.outbox:
			if sealed, ok := c.maybeSealResponse(resp); ok {
				resp = sealed
			}
			if err := c.fc.WriteMessage(resp); err != nil {
				c.log.Debug("write error", "err", err)
				_ = c.fc.Underlying().Close()
				return
			}
		case <-c.connDone:
			return
		}
	}
}

// send queues a response. The buffer must not be modified afterwards.
func (c *conn) send(resp []byte) {
	select {
	case c.outbox <- resp:
	case <-c.connDone:
	}
}

// sendCopy queues a copy of a response built in a shared buffer.
func (c *conn) sendCopy(resp []byte) {
	if len(resp) == 0 {
		return
	}
	c.send(append([]byte(nil), resp...))
}

func (c *request) handleMessage(ctx context.Context, msg []byte) {
	off := 0
	first := true
	chainFailed := false
	lastStatus := uint32(wire.StatusSuccess)
	var lastFileId [16]byte
	prevRespStart := -1
	// Responses are signed once the whole chain is built: appending the next
	// response pads the previous one and sets its NextCommand, and the
	// signature has to cover both (MS-SMB2 3.3.4.1.1).
	type unsigned struct {
		start  int
		signer *signing.Signer
	}
	var toSign []unsigned
	defer func() {
		for i, u := range toSign {
			end := len(c.out)
			if i+1 < len(toSign) {
				end = toSign[i+1].start
			}
			if err := u.signer.Sign(c.out[u.start:end]); err != nil {
				c.log.Debug("sign response failed", "err", err)
			}
		}
	}()

	for off+wire.HeaderSize <= len(msg) {
		sub := msg[off:]
		var hdr wire.Header
		if err := hdr.Parse(sub); err != nil {
			c.log.Debug("bad header in compound", "err", err)
			return
		}
		related := hdr.Flags&wire.FlagRelatedOps != 0 && !first
		if related {
			if fo := fileIdOffset(hdr.Command); fo >= 0 && fo+16 <= len(sub) {
				copy(sub[fo:fo+16], lastFileId[:])
			}
		}

		c.chargeCredits(uint32(hdr.CreditCharge))

		if sess := c.getSession(hdr.SessionId); sess != nil && sess.signer != nil {
			if hdr.Flags&wire.FlagSigned != 0 {
				ok, vErr := sess.signer.Verify(sub)
				if vErr != nil || !ok {
					chainFailed = true
					lastStatus = wire.StatusAccessDenied
				}
			} else if sess.requireSign {
				chainFailed = true
				lastStatus = wire.StatusAccessDenied
			}
		}

		if hdr.Command == wire.CmdChangeNotify && !chainFailed {
			sess := c.getSession(hdr.SessionId)
			var trCN *tree
			if sess != nil {
				trCN = sess.getTree(hdr.TreeId)
			}
			status, pending := c.handleChangeNotify(ctx, sub, &hdr, trCN)
			if pending {
				first = false
				if hdr.NextCommand == 0 {
					break
				}
				off += int(hdr.NextCommand)
				continue
			}
			lastStatus = status
			if status != wire.StatusSuccess && status != wire.StatusMoreProcessingRequired {
				chainFailed = true
			}
		}

		if prevRespStart >= 0 {
			for len(c.out)%8 != 0 {
				c.out = append(c.out, 0)
			}
			delta := uint32(len(c.out) - prevRespStart)
			binary.LittleEndian.PutUint32(c.out[prevRespStart+20:prevRespStart+24], delta)
		}
		respStart := len(c.out)
		c.out = append(c.out, make([]byte, wire.HeaderSize)...)

		var status uint32
		switch {
		case chainFailed:
			status = lastStatus
		case hdr.Command == wire.CmdCancel:
			status = c.handleCancel(sub, &hdr)
		default:
			status = c.dispatch(ctx, sub, &hdr, &lastFileId, related)
		}
		lastStatus = status
		if status != wire.StatusSuccess && status != wire.StatusMoreProcessingRequired {
			chainFailed = true
		}

		// hdr.Credit still holds what the client asked for.
		hdr.Credit = c.grantCredits(hdr.Credit)

		hdr.Flags |= wire.FlagServerToRedir
		if !first {
			hdr.Flags |= wire.FlagRelatedOps
		}
		hdr.Flags &^= wire.FlagAsyncCommand
		hdr.Status = status
		hdr.EncodeAt(c.out[respStart:])

		if hdr.Command == wire.CmdNegotiate || hdr.Command == wire.CmdSessionSetup {
			c.updatePreauth(c.out[respStart:])
		}

		if sess := c.getSession(hdr.SessionId); sess != nil && sess.signer != nil {
			encrypting := sess.requireEncrypt && hdr.Command != wire.CmdNegotiate && hdr.Command != wire.CmdSessionSetup
			if !encrypting {
				hdr.Flags |= wire.FlagSigned
				binary.LittleEndian.PutUint32(c.out[respStart+16:respStart+20], hdr.Flags)
				toSign = append(toSign, unsigned{start: respStart, signer: sess.signer})
			}
		}

		prevRespStart = respStart
		first = false
		if hdr.NextCommand == 0 {
			break
		}
		off += int(hdr.NextCommand)
	}
}

// fileIdOffset returns where the FileId sits in a request, so a related
// compound command can inherit the previous command's handle. The offsets
// are the request layouts in MS-SMB2 section 2.2; getting one wrong makes
// the server answer the chained command with STATUS_FILE_CLOSED.
func fileIdOffset(cmd uint16) int {
	switch cmd {
	case wire.CmdClose, wire.CmdFlush, wire.CmdQueryDirectory, wire.CmdLock, wire.CmdIoctl:
		// StructureSize plus 6 bytes of fixed fields.
		return 64 + 8
	case wire.CmdRead, wire.CmdWrite, wire.CmdSetInfo:
		// Read/Write: length and offset first. SetInfo: buffer fields first.
		return 64 + 16
	case wire.CmdQueryInfo:
		// Info class, buffer lengths, additional information, and flags.
		return 64 + 24
	default:
		return -1
	}
}

// chargeCredits deducts what a request costs, never below zero. Every request
// uses at least one credit, including those with a CreditCharge of zero.
func (c *conn) chargeCredits(charge uint32) {
	charge = max(charge, 1)
	c.creditMu.Lock()
	defer c.creditMu.Unlock()
	if c.creditBalance >= charge {
		c.creditBalance -= charge
		return
	}
	c.creditBalance = 0
}

// grantCredits grants the credits a client requested, as far as the
// server's maximum allows, and at least one while the client has none left.
//
// Granting only what was asked matters: topping the client up to the maximum
// in the NEGOTIATE response, which macOS does not count, left it believing it
// had a single credit, so it stalled before every compound request and
// eventually hung.
func (c *conn) grantCredits(requested uint16) uint16 {
	c.creditMu.Lock()
	defer c.creditMu.Unlock()
	grant := uint32(requested)
	if room := c.srv.maxCredits - min(c.creditBalance, c.srv.maxCredits); grant > room {
		grant = room
	}
	if grant == 0 && c.creditBalance == 0 {
		grant = 1
	}
	c.creditBalance += grant
	return uint16(grant)
}

func (c *conn) getSession(id uint64) *session {
	c.sessionsMu.RLock()
	defer c.sessionsMu.RUnlock()
	return c.sessions[id]
}

func (c *conn) putSession(id uint64, sess *session) {
	c.sessionsMu.Lock()
	defer c.sessionsMu.Unlock()
	c.sessions[id] = sess
}

func (c *conn) dropSession(id uint64) {
	c.sessionsMu.Lock()
	defer c.sessionsMu.Unlock()
	delete(c.sessions, id)
}

// eachSession calls fn for every session on the connection.
func (c *conn) eachSession(fn func(*session)) {
	c.sessionsMu.RLock()
	sessions := make([]*session, 0, len(c.sessions))
	for _, sess := range c.sessions {
		sessions = append(sessions, sess)
	}
	c.sessionsMu.RUnlock()
	for _, sess := range sessions {
		fn(sess)
	}
}

func (c *conn) cleanup() {
	close(c.connDone)
	c.handlers.Wait()
	// Let the writer finish what it has queued, but do not wait on a client
	// that has stopped reading.
	select {
	case <-c.writerDone:
	case <-time.After(cleanupCloseTimeout):
	}
	c.pendingMu.Lock()
	for _, op := range c.pending {
		op.cancel()
	}
	c.pending = nil
	c.pendingByMsg = nil
	c.pendingMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), cleanupCloseTimeout)
	defer cancel()
	c.eachSession(func(sess *session) {
		for _, tr := range sess.allTrees() {
			c.closeAllOpens(ctx, tr)
		}
	})
}

func (c *conn) updatePreauth(msg []byte) {
	if len(c.preauthHash) == 0 {
		return
	}
	sha := sha512.New()
	sha.Write(c.preauthHash)
	sha.Write(msg)
	c.preauthHash = sha.Sum(nil)
}

func (s *session) getTree(id uint32) *tree {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.trees[id]
}

func (s *session) addTree(id uint32, t *tree) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.trees[id] = t
}

func (s *session) dropTree(id uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.trees, id)
}

// allTrees is a snapshot of the session's tree connects.
func (s *session) allTrees() []*tree {
	s.mu.RLock()
	defer s.mu.RUnlock()
	trees := make([]*tree, 0, len(s.trees))
	for _, t := range s.trees {
		trees = append(trees, t)
	}
	return trees
}
