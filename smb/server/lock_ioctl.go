package server

import (
	"context"

	"github.com/sonroyaalmerol/go-smb-server/smb/vfs"
	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

func (c *conn) handleLock(_ context.Context, msg []byte, hdr *wire.Header, tr *tree) uint32 {
	var req wire.LockRequest
	if err := req.Parse(msg); err != nil {
		return c.errBody(wire.StatusInvalidParameter)
	}
	oh, ok := tr.opens[req.FileId]
	if !ok {
		return c.errBody(wire.StatusInvalidHandle)
	}

	locker := c.srv.lockTable()
	owner := lockOwner(hdr.SessionId, req.FileId)
	// Locks granted in this request are undone if a later element in the
	// same request fails, so a rejected request changes nothing.
	var granted []vfs.LockRange
	unwind := func() {
		for _, r := range granted {
			_ = locker.Unlock(owner, oh.path, r)
		}
	}

	for _, l := range req.Locks {
		if l.Flags&wire.LockFlagUnlock != 0 {
			if err := locker.Unlock(owner, oh.path, lockRange(l.Offset, l.Length, false)); err != nil {
				unwind()
				c.log.Debug("unlock failed", "path", oh.path, "err", err)
				return c.errBody(wire.StatusInvalidParameter)
			}
			continue
		}

		exclusive := l.Flags&wire.LockFlagExclusiveLock != 0
		if !exclusive && l.Flags&wire.LockFlagSharedLock == 0 {
			unwind()
			return c.errBody(wire.StatusInvalidParameter)
		}
		r := lockRange(l.Offset, l.Length, exclusive)
		if r.Start >= r.End {
			// A zero-length lock covers no bytes and conflicts with nothing.
			continue
		}
		conflict, err := locker.Lock(owner, oh.path, r)
		if err != nil {
			unwind()
			c.log.Debug("lock failed", "path", oh.path, "err", err)
			return c.errBody(wire.StatusLockNotGranted)
		}
		if conflict != nil {
			unwind()
			// Blocking locks are not supported: a request that cannot be
			// granted is refused whether or not FAIL_IMMEDIATELY is set.
			return c.errBody(wire.StatusLockNotGranted)
		}
		granted = append(granted, r)
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
		resp := buildValidateNegotiateInfo(c.negDialect, c.negCaps, c.srv.guid)
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
					c.out = wire.IoctlResponseAppend(c.out, req.CtlCode, req.FileId, nil, result, req.Flags)
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

// buildValidateNegotiateInfo echoes the capabilities, GUID, security mode,
// and dialect from this connection's NEGOTIATE response, which is what the
// client validates against.
func buildValidateNegotiateInfo(dialect uint16, caps uint32, guid [16]byte) []byte {
	out := make([]byte, 24)
	for i := range 4 {
		out[i] = byte(caps >> (8 * i))
	}
	copy(out[4:20], guid[:])
	out[20] = byte(wire.SigningEnabled)
	out[21] = 0
	out[22] = byte(dialect)
	out[23] = byte(dialect >> 8)
	return out
}
