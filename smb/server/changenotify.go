package server

import (
	"context"
	"errors"
	"time"

	"github.com/sonroyaalmerol/go-smb-server/smb/vfs"
	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

const (
	FileNotifyChangeFileName   uint32 = 0x00000001
	FileNotifyChangeDirName    uint32 = 0x00000002
	FileNotifyChangeAttributes uint32 = 0x00000004
	FileNotifyChangeSize       uint32 = 0x00000008
	FileNotifyChangeLastWrite  uint32 = 0x00000010
	FileNotifyChangeLastAccess uint32 = 0x00000020
	FileNotifyChangeCreation   uint32 = 0x00000040
	FileNotifyChangeEA         uint32 = 0x00000080
	FileNotifyChangeSecurity   uint32 = 0x00000100
	SMB2WatchTree              uint16 = 0x0001
)

const (
	fileActionAdded    uint32 = 0x00000001
	fileActionRemoved  uint32 = 0x00000002
	fileActionModified uint32 = 0x00000003
	fileActionRenamed  uint32 = 0x00000004
)

type ChangeNotifyRequest struct {
	Flags              uint16
	OutputBufferLength uint32
	FileId             [16]byte
	CompletionFilter   uint32
}

func (r *ChangeNotifyRequest) Parse(msg []byte) error {
	if len(msg) < 64+32 {
		return errors.New("wire: change_notify needs 32 bytes")
	}
	b := msg[64:]
	r.Flags = le16(b[2:4])
	r.OutputBufferLength = le32(b[4:8])
	copy(r.FileId[:], b[8:24])
	r.CompletionFilter = le32(b[24:28])
	return nil
}

type notifyEvent struct {
	action uint32
	name   string
}

func (c *conn) handleChangeNotify(ctx context.Context, msg []byte, hdr *wire.Header, tr *tree) (uint32, bool) {
	var req ChangeNotifyRequest
	if err := req.Parse(msg); err != nil {
		return c.errBody(wire.StatusInvalidParameter), false
	}
	oh, ok := tr.opens[req.FileId]
	if !ok {
		return c.errBody(wire.StatusInvalidHandle), false
	}

	op := c.registerPending(hdr.MessageId)
	c.out = append(c.out, c.buildAsyncInterim(hdr, op.asyncID)...)

	snap := snapshotEntries(oh.h, ctx)
	go c.watchDirectory(ctx, op, *hdr, oh.h, snap, req)
	return wire.StatusPending, true
}

func (c *conn) watchDirectory(ctx context.Context, op *pendingOp, hdr wire.Header, h vfs.Handle, snap map[string]uint64, req ChangeNotifyRequest) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.finalizeCN(op, hdr, wire.StatusCancelled, nil)
			return
		case <-op.done:
			c.finalizeCN(op, hdr, wire.StatusCancelled, nil)
			return
		case <-ticker.C:
		}
		cur := snapshotEntries(h, ctx)
		if events := diffEntries(snap, cur, req.CompletionFilter); len(events) > 0 {
			body := buildChangeNotifyBody(events, req.OutputBufferLength)
			c.finalizeCN(op, hdr, wire.StatusSuccess, body)
			return
		}
	}
}

func (c *conn) finalizeCN(op *pendingOp, hdr wire.Header, status uint32, body []byte) {
	c.unregister(op)
	c.sendFinal(finalizeAsync(&hdr, op.asyncID, status, body))
}

func snapshotEntries(h vfs.Handle, ctx context.Context) map[string]uint64 {
	out := make(map[string]uint64)
	for fi, err := range h.Enumerate(ctx, "*") {
		if err != nil {
			return out
		}
		out[fi.Name] = uint64(fi.Size)
	}
	return out
}

func diffEntries(old, cur map[string]uint64, filter uint32) []notifyEvent {
	var events []notifyEvent
	for name, sz := range cur {
		osz, existed := old[name]
		if !existed {
			events = append(events, notifyEvent{action: fileActionAdded, name: name})
			continue
		}
		if osz != sz && filter&FileNotifyChangeSize != 0 {
			events = append(events, notifyEvent{action: fileActionModified, name: name})
		}
	}
	if filter&(FileNotifyChangeFileName|FileNotifyChangeDirName) != 0 {
		for name := range old {
			if _, ok := cur[name]; !ok {
				events = append(events, notifyEvent{action: fileActionRemoved, name: name})
			}
		}
	}
	return events
}

func buildChangeNotifyBody(events []notifyEvent, maxLen uint32) []byte {
	var out []byte
	for _, e := range events {
		name := wire.UTF16ToBytes(e.name)
		const fixed = 12
		if uint32(len(out)+fixed+len(name)) > maxLen {
			break
		}
		start := len(out)
		out = append(out, make([]byte, fixed)...)
		out = append(out, name...)
		le32Put(out[start+4:start+8], e.action)
		le32Put(out[start+8:start+12], uint32(len(name)))
	}
	return out
}

func (c *conn) handleCancel(_ []byte, hdr *wire.Header) uint32 {
	c.cancelPending(hdr.AsyncId)
	c.out = append(c.out, 0x04, 0x00, 0x00, 0x00)
	return wire.StatusSuccess
}
