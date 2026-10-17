package server

import (
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
	addr        string
	authFactory auth.Factory
	shares      []vfs.Share
	shareByName map[string]vfs.Share
	dialect     uint16
	maxTransact uint32
	maxRead     uint32
	maxWrite    uint32
	maxCredits  uint32
	requireEnc  bool
	log         *slog.Logger
	guid        [16]byte

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

func WithDialect(d uint16) Option { return func(s *Server) { s.dialect = d } }

func New(opts ...Option) (*Server, error) {
	s := &Server{
		addr:        ":445",
		dialect:     wire.DialectSMB302,
		maxTransact: defaultMaxTransact,
		maxRead:     defaultMaxRead,
		maxWrite:    defaultMaxWrite,
		maxCredits:  defaultMaxCredits,
		log:         slog.Default(),
	}
	for _, opt := range opts {
		opt(s)
	}
	if len(s.shares) == 0 {
		return nil, errors.New("server: at least one share is required")
	}
	if s.authFactory == nil {
		// Authentication must be explicitly configured. Silently installing
		// an allow-all authenticator would expose every configured share to
		// unauthenticated clients when the caller omits WithAuth.
		return nil, errors.New("server: authentication factory is required")
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
	opens   map[[16]byte]*openHandle
	nextID  uint64
	locks   *lockMgrSet
	oplocks *oplockTable
}

type openHandle struct {
	h             vfs.Handle
	fileId        [16]byte
	path          string
	deletePending bool
	enumDone      bool
	enumMu        sync.Mutex
}

type conn struct {
	srv           *Server
	fc            *transport.FramedConn
	log           *slog.Logger
	out           []byte
	sessions      map[uint64]*session
	nextSess      uint64
	creditBalance uint32

	nextAsync    uint64
	pending      map[uint64]*pendingOp
	pendingByMsg map[uint64]*pendingOp
	pendingMu    sync.Mutex
	asyncResp    chan []byte
	connDone     chan struct{}

	preauthHash []byte
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
		asyncResp:     make(chan []byte, 64),
		connDone:      make(chan struct{}),
		preauthHash:   sha.Sum(nil),
	}
	defer cn.cleanup()

	for {
		if err := ctx.Err(); err != nil {
			return
		}
		if !cn.drainAsync() {
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

		if len(msg) >= 4 && msg[0] == 0xFD {
			dec, dErr := cn.openTransform(msg)
			if dErr != nil {
				cn.log.Debug("decrypt error", "err", dErr)
				return
			}
			msg = dec
		} else if len(msg) >= wire.HeaderSize {
			sessID := binary.LittleEndian.Uint64(msg[40:48])
			if sess := cn.getSession(sessID); sess != nil && sess.requireEncrypt {
				cn.log.Debug("plaintext on encrypted session, dropping")
				return
			}
		}

		cn.out = cn.out[:0]
		cmdBefore := uint16(0)
		if len(msg) >= wire.HeaderSize {
			cmdBefore = binary.LittleEndian.Uint16(msg[12:14])
		}
		if cmdBefore == wire.CmdNegotiate || cmdBefore == wire.CmdSessionSetup {
			cn.updatePreauth(msg)
		}
		cn.handleMessage(connCtx, msg)
		if len(cn.out) > 0 {
			sealed, err := cn.maybeSealResponse(cn.out)
			if err != nil {
				cn.log.Debug("response encryption failed", "err", err)
				return
			}
			if err := cn.fc.WriteMessage(sealed); err != nil {
				cn.log.Debug("write error", "err", err)
				return
			}
		}
	}
}

// drainAsync applies the same response-encryption policy as the
// synchronous writer. A sealing or write failure terminates the
// connection's response path rather than exposing plaintext.
func (c *conn) drainAsync() bool {
	for {
		select {
		case resp := <-c.asyncResp:
			sealed, err := c.maybeSealResponse(resp)
			if err != nil {
				c.log.Debug("async response encryption failed", "err", err)
				return false
			}
			if err := c.fc.WriteMessage(sealed); err != nil {
				c.log.Debug("write async error", "err", err)
				return false
			}
		default:
			return true
		}
	}
}

// validateCompoundRequest checks the entire request chain before dispatch.
// MS-SMB2 compound commands use eight-byte-aligned NextCommand offsets.
// Prevalidation prevents a malformed later command from leaving a partial
// response eligible for transmission.
func validateCompoundRequest(msg []byte) error {
	if len(msg) < wire.HeaderSize {
		return errors.New("server: truncated compound request")
	}

	for off := 0; off < len(msg); {
		if len(msg)-off < wire.HeaderSize {
			return errors.New("server: truncated compound header")
		}

		var hdr wire.Header
		if err := hdr.Parse(msg[off:]); err != nil {
			return fmt.Errorf("server: malformed compound header: %w", err)
		}

		if hdr.NextCommand == 0 {
			return nil
		}

		if hdr.NextCommand < wire.HeaderSize ||
			hdr.NextCommand%8 != 0 ||
			uint64(hdr.NextCommand) > uint64(len(msg)-off-wire.HeaderSize) {
			return errors.New("server: invalid compound request offset")
		}

		off += int(hdr.NextCommand)
	}

	return errors.New("server: malformed compound request")
}

func (c *conn) handleMessage(ctx context.Context, msg []byte) {
	// Validate the complete chain before executing any operation.
	if err := validateCompoundRequest(msg); err != nil {
		c.log.Debug("reject malformed compound request", "err", err)
		c.out = c.out[:0]
		return
	}

	off := 0
	first := true
	chainFailed := false
	lastStatus := uint32(wire.StatusSuccess)
	var lastFileId [16]byte
	prevRespStart := -1

	for off+wire.HeaderSize <= len(msg) {
		sub := msg[off:]
		var hdr wire.Header
		if err := hdr.Parse(sub); err != nil {
			c.log.Debug("bad header in compound", "err", err)
			return
		}
		// Verify the original bounded command before any related-operation
		// substitution. NextCommand is part of the signed SMB header.
		end := len(sub)
		if hdr.NextCommand != 0 {
			end = int(hdr.NextCommand)
		}
		part := sub[:end]
		if err := verifyCompoundRequestSignature(
			c.getSession(hdr.SessionId), &hdr, part,
		); err != nil {
			chainFailed = true
			lastStatus = wire.StatusAccessDenied
		}

		related := hdr.Flags&wire.FlagRelatedOps != 0 && !first
		if related && !chainFailed {
			if fo := fileIdOffset(hdr.Command); fo >= 0 && fo+16 <= len(part) {
				copy(part[fo:fo+16], lastFileId[:])
			}
		}

		charge := uint32(hdr.CreditCharge)
		if c.creditBalance >= charge {
			c.creditBalance -= charge
		} else {
			c.creditBalance = 0
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

		grant := c.srv.maxCredits - c.creditBalance
		c.creditBalance += grant
		if grant > 0xFFFF {
			hdr.Credit = 0xFFFF
		} else {
			hdr.Credit = uint16(grant)
		}

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

		// Sign after all compound offsets have been finalized.
		// SMB signatures cover NextCommand, so signing here would
		// authenticate a header that may subsequently be modified.

		prevRespStart = respStart
		first = false
		if hdr.NextCommand == 0 {
			break
		}
		off += int(hdr.NextCommand)
	}

	// A compound response must be fully assembled before signing.
	// Never transmit a partially signed response.
	if err := c.signResponseChain(); err != nil {
		c.log.Debug("response signing failed", "err", err)
		c.out = c.out[:0]
	}
}

// signResponseChain signs finalized SMB2 response segments.
// See MS-SMB2: compound responses and SMB2 header NextCommand.
// Any failure prevents the caller from transmitting the response.
func (c *conn) signResponseChain() error {
	for off := 0; off < len(c.out); {
		if len(c.out)-off < wire.HeaderSize {
			return errors.New("server: truncated compound response")
		}

		sub := c.out[off:]
		var hdr wire.Header
		if err := hdr.Parse(sub); err != nil {
			return fmt.Errorf("server: invalid response header: %w", err)
		}

		end := len(c.out)
		if hdr.NextCommand != 0 {
			if hdr.NextCommand < wire.HeaderSize ||
				uint64(hdr.NextCommand) > uint64(len(sub)) ||
				hdr.NextCommand%8 != 0 {
				return errors.New("server: invalid compound response offset")
			}
			end = off + int(hdr.NextCommand)
		}

		if sess := c.getSession(hdr.SessionId); sess != nil && sess.signer != nil {
			encrypting := sess.requireEncrypt &&
				hdr.Command != wire.CmdNegotiate &&
				hdr.Command != wire.CmdSessionSetup

			if !encrypting {
				part := c.out[off:end]
				hdr.Flags |= wire.FlagSigned
				binary.LittleEndian.PutUint32(part[16:20], hdr.Flags)

				if err := sess.signer.Sign(part); err != nil {
					return fmt.Errorf("server: sign response: %w", err)
				}
			}
		}

		off = end
	}
	return nil
}

// verifyCompoundRequestSignature authenticates one bounded SMB command.
// MS-SMB2 compound signing covers the individual command, including its
// finalized NextCommand field. Verify mutates its input, so use a copy to
// preserve the original request bytes for subsequent processing.
func verifyCompoundRequestSignature(
	sess *session, hdr *wire.Header, part []byte,
) error {
	if sess == nil {
		// Unknown sessions are rejected by dispatch's session checks.
		return nil
	}
	if sess.authenticated && sess.signer == nil {
		return errors.New("server: authenticated session missing signer")
	}
	if hdr.Flags&wire.FlagSigned == 0 {
		if sess.requireSign {
			return errors.New("server: required request signature missing")
		}
		return nil
	}
	if sess.signer == nil {
		return errors.New("server: signed request without signer")
	}

	signed := append([]byte(nil), part...)
	ok, err := sess.signer.Verify(signed)
	if err != nil {
		return fmt.Errorf("server: request signature verification: %w", err)
	}
	if !ok {
		return errors.New("server: invalid request signature")
	}
	return nil
}

func fileIdOffset(cmd uint16) int {
	switch cmd {
	case wire.CmdClose, wire.CmdFlush, wire.CmdQueryDirectory, wire.CmdQueryInfo, wire.CmdSetInfo:
		return 64 + 8
	case wire.CmdRead, wire.CmdWrite, wire.CmdLock, wire.CmdIoctl:
		return 64 + 16
	default:
		return -1
	}
}

func (c *conn) getSession(id uint64) *session { return c.sessions[id] }

func (c *conn) cleanup() {
	close(c.connDone)
	c.pendingMu.Lock()
	for _, op := range c.pending {
		op.cancel()
	}
	c.pending = nil
	c.pendingByMsg = nil
	c.pendingMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), cleanupCloseTimeout)
	defer cancel()
	for _, sess := range c.sessions {
		for _, tr := range sess.trees {
			c.closeAllOpens(ctx, tr)
		}
	}
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

func (s *session) getTree(id uint32) *tree { return s.trees[id] }
