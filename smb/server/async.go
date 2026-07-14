package server

import (
	"sync"

	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

type pendingOp struct {
	asyncID   uint64
	messageID uint64
	done      chan struct{}
	once      sync.Once
}

func (p *pendingOp) cancel() {
	p.once.Do(func() { close(p.done) })
}

func (c *conn) registerPending(messageID uint64) *pendingOp {
	c.nextAsync++
	op := &pendingOp{
		asyncID:   c.nextAsync,
		messageID: messageID,
		done:      make(chan struct{}),
	}
	c.pendingMu.Lock()
	c.pending[op.asyncID] = op
	c.pendingByMsg[messageID] = op
	c.pendingMu.Unlock()
	return op
}

func (c *conn) unregister(op *pendingOp) {
	c.pendingMu.Lock()
	delete(c.pending, op.asyncID)
	delete(c.pendingByMsg, op.messageID)
	c.pendingMu.Unlock()
}

func (c *conn) cancelPending(asyncID uint64) *pendingOp {
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()
	if op, ok := c.pending[asyncID]; ok {
		op.cancel()
		return op
	}
	return nil
}

func (c *conn) sendFinal(msg []byte) {
	select {
	case c.asyncResp <- msg:
	default:
	}
}

func (c *conn) buildAsyncInterim(hdr *wire.Header, asyncID uint64) []byte {
	resp := *hdr
	resp.Flags = wire.FlagServerToRedir | wire.FlagAsyncCommand
	resp.Status = wire.StatusPending
	resp.AsyncId = asyncID
	resp.Credit = 0
	return resp.Append(nil)
}

func finalizeAsync(hdr *wire.Header, asyncID uint64, status uint32, body []byte) []byte {
	resp := *hdr
	resp.Flags = wire.FlagServerToRedir | wire.FlagAsyncCommand
	resp.Status = status
	resp.AsyncId = asyncID
	out := resp.Append(nil)
	return append(out, body...)
}

func le16(b []byte) uint16 { return uint16(b[0]) | uint16(b[1])<<8 }

func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func le32Put(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}
