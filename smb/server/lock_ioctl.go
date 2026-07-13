package server

import (
	"context"
	"sync"

	"github.com/sonroyaalmerol/go-smb-server/smb/vfs"
	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

type lockRange struct {
	start, end uint64
	exclusive  bool
}

type lockManager struct {
	mu     sync.Mutex
	ranges []lockRange
}

type lockMgrSet struct {
	mu   sync.Mutex
	mgrs map[string]*lockManager
}

func newLockMgrSet() *lockMgrSet {
	return &lockMgrSet{mgrs: make(map[string]*lockManager)}
}

func (s *lockMgrSet) manager(path string) *lockManager {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.mgrs[path]
	if !ok {
		m = &lockManager{}
		s.mgrs[path] = m
	}
	return m
}

func (m *lockManager) conflicts(start, end uint64, exclusive bool) (int, bool) {
	for i, r := range m.ranges {
		overlap := start < r.end && r.start < end
		if overlap && (r.exclusive || exclusive) {
			return i, true
		}
	}
	return -1, false
}

func (m *lockManager) tryLock(start, length uint64, exclusive, failImmediately bool) bool {
	end := start + length
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, conflict := m.conflicts(start, end, exclusive); conflict {
		if failImmediately {
			return false
		}
		return false
	}
	m.ranges = append(m.ranges, lockRange{start: start, end: end, exclusive: exclusive})
	return true
}

func (m *lockManager) unlock(start, length uint64) {
	end := start + length
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, r := range m.ranges {
		if r.start == start && r.end == end {
			m.ranges = append(m.ranges[:i], m.ranges[i+1:]...)
			return
		}
	}
}

func (c *conn) handleLock(_ context.Context, msg []byte, tr *tree) uint32 {
	var req wire.LockRequest
	if err := req.Parse(msg); err != nil {
		return c.errBody(wire.StatusInvalidParameter)
	}
	oh, ok := tr.opens[req.FileId]
	if !ok {
		return c.errBody(wire.StatusInvalidHandle)
	}
	lm := tr.locks.manager(oh.path)
	for _, l := range req.Locks {
		switch {
		case l.Flags&wire.LockFlagUnlock != 0:
			lm.unlock(l.Offset, l.Length)
		case l.Flags&wire.LockFlagExclusiveLock != 0:
			if !lm.tryLock(l.Offset, l.Length, true, l.Flags&wire.LockFlagFailImmediately != 0) {
				return c.errBody(wire.StatusLockConflict)
			}
		case l.Flags&wire.LockFlagSharedLock != 0:
			if !lm.tryLock(l.Offset, l.Length, false, l.Flags&wire.LockFlagFailImmediately != 0) {
				return c.errBody(wire.StatusLockConflict)
			}
		default:
			return c.errBody(wire.StatusInvalidParameter)
		}
	}
	c.out = wire.LockResponseAppend(c.out)
	return wire.StatusSuccess
}

func (c *conn) handleIoctl(ctx context.Context, msg []byte, tr *tree) uint32 {
	var req wire.IoctlRequest
	if err := req.Parse(msg); err != nil {
		return c.errBody(wire.StatusInvalidParameter)
	}
	switch req.CtlCode {
	case wire.FSCTLValidateNegotiateInfo:
		resp := buildValidateNegotiateInfo(c.srv.dialect, c.srv.guid)
		c.out = wire.IoctlResponseAppend(c.out, req.CtlCode, req.FileId, nil, resp, req.Flags)
		return wire.StatusSuccess
	case wire.FSCTLQueryNetworkInterfaceInfo:
		c.out = wire.IoctlResponseAppend(c.out, req.CtlCode, req.FileId, nil, nil, req.Flags)
		return wire.StatusSuccess
	case wire.FSCTLPipeWait:
		c.out = wire.IoctlResponseAppend(c.out, req.CtlCode, req.FileId, nil, nil, req.Flags)
		return wire.StatusSuccess
	case wire.FSCTLPipeTransceive:
		if tr != nil {
			if oh, ok := tr.opens[req.FileId]; ok {
				if pp, ok2 := oh.h.(vfs.PipeProcessor); ok2 {
					result := pp.ProcessPipe(ctx, req.Input)
					c.out = wire.IoctlResponseAppend(c.out, req.CtlCode, req.FileId, req.Input, result, req.Flags)
					return wire.StatusSuccess
				}
			}
		}
		return c.errBody(wire.StatusNotSupported)
	default:
		if tr == nil {
			return c.errBody(wire.StatusInvalidDeviceRequest)
		}
		if _, ok := tr.opens[req.FileId]; !ok {
			return c.errBody(wire.StatusInvalidHandle)
		}
		return c.errBody(wire.StatusNotSupported)
	}
}

func buildValidateNegotiateInfo(dialect uint16, guid [16]byte) []byte {
	out := make([]byte, 24)
	for i := range 4 {
		out[i] = byte(wire.CapLargeMTU >> (8 * i))
	}
	copy(out[4:20], guid[:])
	out[20] = byte(wire.SigningEnabled)
	out[21] = 0
	out[22] = byte(dialect)
	out[23] = byte(dialect >> 8)
	return out
}
