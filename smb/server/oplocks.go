package server

import (
	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

type oplockTable struct {
	byPath map[string]*oplockInfo
}

type oplockInfo struct {
	fileId [16]byte
	sessID uint64
	treeID uint32
	path   string
}

func newOplockTable() *oplockTable {
	return &oplockTable{byPath: make(map[string]*oplockInfo)}
}

func (ot *oplockTable) grant(path string, info *oplockInfo) bool {
	_, exists := ot.byPath[path]
	if exists {
		return false
	}
	ot.byPath[path] = info
	return true
}

func (ot *oplockTable) breakOplock(path string) *oplockInfo {
	existing, exists := ot.byPath[path]
	if !exists {
		return nil
	}
	delete(ot.byPath, path)
	return existing
}

func (ot *oplockTable) release(path string) {
	delete(ot.byPath, path)
}

func (c *conn) sendOplockBreak(info *oplockInfo) {
	var msg [88]byte
	msg[0], msg[1], msg[2], msg[3] = 0xFE, 'S', 'M', 'B'
	le32Put(msg[4:8], 64)
	le32Put(msg[8:12], 0)
	putLE16(msg[12:14], wire.CmdOplockBreak)
	putLE16(msg[14:16], 0)
	le32Put(msg[16:20], uint32(wire.FlagServerToRedir|wire.FlagAsyncCommand))
	le32Put(msg[20:24], 0)
	le32Put(msg[24:28], 0)
	le32Put(msg[28:32], 0)
	le32Put(msg[32:36], 0)
	le32Put(msg[36:40], info.treeID)
	le64Put(msg[40:48], info.sessID)
	for i := range 16 {
		msg[48+i] = 0
	}
	msg[64] = 1
	msg[65] = 0
	le16Put(msg[66:68], 24)
	msg[68] = 1
	msg[69] = 0
	msg[70] = 0
	msg[71] = 0
	copy(msg[72:88], info.fileId[:])
	select {
	case c.asyncResp <- msg[:]:
	case <-c.connDone:
	}
}

func (c *conn) handleOplockBreak(msg []byte) uint32 {
	if len(msg) < wire.HeaderSize+24 {
		return c.errBody(wire.StatusInvalidParameter)
	}
	var resp [24]byte
	resp[0], resp[1] = 0x18, 0x00
	resp[3], resp[7] = 0, 0
	msg[8], msg[9], msg[10], msg[11] = 0, 0, 0, 0
	c.out = append(c.out, resp[:]...)
	return wire.StatusSuccess
}

func le16Put(b []byte, v uint16) { b[0], b[1] = byte(v), byte(v>>8) }
func putLE16(b []byte, v uint16) { b[0], b[1] = byte(v), byte(v>>8) }

func le64Put(b []byte, v uint64) {
	for i := range 8 {
		b[i] = byte(v >> (8 * i))
	}
}
