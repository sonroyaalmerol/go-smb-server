package server

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/sonroyaalmerol/go-smb-server/smb/auth"
	"github.com/sonroyaalmerol/go-smb-server/smb/transport"
	"github.com/sonroyaalmerol/go-smb-server/smb/vfs"
	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

const (
	defaultMaxTransact uint32 = 65536
	defaultMaxRead     uint32 = 1 << 20
	defaultMaxWrite    uint32 = 1 << 20
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
	log         *slog.Logger
	guid        [16]byte
}

type Option func(*Server)

func WithAddr(addr string) Option { return func(s *Server) { s.addr = addr } }

func WithAuth(f auth.Factory) Option { return func(s *Server) { s.authFactory = f } }

func WithShares(shares ...vfs.Share) Option {
	return func(s *Server) { s.shares = append(s.shares, shares...) }
}

func WithLogger(l *slog.Logger) Option { return func(s *Server) { s.log = l } }

func WithDialect(d uint16) Option { return func(s *Server) { s.dialect = d } }

func New(opts ...Option) (*Server, error) {
	s := &Server{
		addr:        ":445",
		dialect:     wire.DialectSMB302,
		maxTransact: defaultMaxTransact,
		maxRead:     defaultMaxRead,
		maxWrite:    defaultMaxWrite,
		log:         slog.Default(),
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
	defer ln.Close()
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

type session struct {
	auth          auth.Authenticator
	identity      *auth.Identity
	authenticated bool
	trees         map[uint32]*tree
	nextTreeID    uint32
}

type tree struct {
	share  vfs.Share
	opens  map[[16]byte]*openHandle
	nextID uint64
}

type openHandle struct {
	h      vfs.Handle
	fileId [16]byte
}

type conn struct {
	srv      *Server
	fc       *transport.FramedConn
	log      *slog.Logger
	out      []byte
	sessions map[uint64]*session
	nextSess uint64
}

func (s *Server) serveConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	cn := &conn{
		srv:      s,
		fc:       transport.NewFramedConn(c),
		log:      s.log,
		sessions: make(map[uint64]*session),
	}

	for {
		if err := ctx.Err(); err != nil {
			return
		}
		msg, err := cn.fc.ReadMessage()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				cn.log.Debug("read error", "err", err)
			}
			return
		}
		cn.out = cn.out[:0]
		cn.handleMessage(ctx, msg)
		if len(cn.out) > 0 {
			if err := cn.fc.WriteMessage(cn.out); err != nil {
				cn.log.Debug("write error", "err", err)
				return
			}
		}
	}
}

func (c *conn) handleMessage(ctx context.Context, msg []byte) {
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
		related := hdr.Flags&wire.FlagRelatedOps != 0 && !first
		if related {
			if fo := fileIdOffset(hdr.Command); fo >= 0 && fo+16 <= len(sub) {
				copy(sub[fo:fo+16], lastFileId[:])
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
		default:
			status = c.dispatch(ctx, sub, &hdr, &lastFileId, related)
		}
		lastStatus = status
		c.log.Info("dispatched", "cmd", hdr.Command, "status", status, "sess", hdr.SessionId, "tree", hdr.TreeId)
		if status != wire.StatusSuccess && status != wire.StatusMoreProcessingRequired {
			chainFailed = true
		}

		hdr.Flags |= wire.FlagServerToRedir
		if !first {
			hdr.Flags |= wire.FlagRelatedOps
		}
		hdr.Flags &^= wire.FlagAsyncCommand
		hdr.Status = status
		hdr.EncodeAt(c.out[respStart:])

		prevRespStart = respStart
		first = false
		if hdr.NextCommand == 0 {
			break
		}
		off += int(hdr.NextCommand)
	}
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

func (s *session) getTree(id uint32) *tree { return s.trees[id] }
