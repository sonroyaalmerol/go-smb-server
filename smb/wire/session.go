package wire

import (
	"encoding/binary"
	"fmt"
)

type SessionSetupRequest struct {
	Flags             uint8
	SecurityMode      uint8
	Capabilities      uint32
	PreviousSessionId uint64
	SecurityBuffer    []byte
}

func (r *SessionSetupRequest) Parse(msg []byte) error {
	const body = 64
	if len(msg) < body+24 {
		return fmt.Errorf("wire: session_setup needs %d bytes, got %d", body+24, len(msg))
	}
	if ss := binary.LittleEndian.Uint16(msg[body : body+2]); ss != 25 {
		return fmt.Errorf("wire: session_setup StructureSize = %d, want 25", ss)
	}
	r.Flags = msg[body+2]
	r.SecurityMode = msg[body+3]
	r.Capabilities = binary.LittleEndian.Uint32(msg[body+4 : body+8])
	secOff := int(binary.LittleEndian.Uint16(msg[body+12 : body+14]))
	secLen := int(binary.LittleEndian.Uint16(msg[body+14 : body+16]))
	r.PreviousSessionId = binary.LittleEndian.Uint64(msg[body+16 : body+24])
	if secOff+secLen > len(msg) {
		return fmt.Errorf("wire: session_setup security buffer out of range (%d:%d, msg=%d)", secOff, secLen, len(msg))
	}
	r.SecurityBuffer = msg[secOff : secOff+secLen]
	return nil
}

type SessionSetupResponse struct {
	SessionFlags   uint16
	SecurityBuffer []byte
}

func (r *SessionSetupResponse) Append(dst []byte) []byte {
	const fixed = 8
	start := len(dst)
	out := append(dst, make([]byte, fixed+len(r.SecurityBuffer))...)
	b := out[start:]
	put16(b[0:2], 9)
	put16(b[2:4], r.SessionFlags)
	put16(b[4:6], uint16(start+fixed))
	put16(b[6:8], uint16(len(r.SecurityBuffer)))
	copy(b[fixed:], r.SecurityBuffer)
	return out
}

func appendSimpleResponse(dst []byte) []byte {
	return append(dst, 0x04, 0x00, 0x00, 0x00)
}

type TreeConnectRequest struct {
	Flags uint16
	Path  []byte
}

func (r *TreeConnectRequest) Parse(msg []byte) error {
	const body = 64
	if len(msg) < body+8 {
		return fmt.Errorf("wire: tree_connect needs %d bytes, got %d", body+8, len(msg))
	}
	if ss := binary.LittleEndian.Uint16(msg[body : body+2]); ss != 9 {
		return fmt.Errorf("wire: tree_connect StructureSize = %d, want 9", ss)
	}
	r.Flags = binary.LittleEndian.Uint16(msg[body+2 : body+4])
	pathOff := int(binary.LittleEndian.Uint16(msg[body+4 : body+6]))
	pathLen := int(binary.LittleEndian.Uint16(msg[body+6 : body+8]))
	if pathOff+pathLen > len(msg) {
		return fmt.Errorf("wire: tree_connect path out of range")
	}
	r.Path = msg[pathOff : pathOff+pathLen]
	return nil
}

type TreeConnectResponse struct {
	ShareType     uint8
	ShareFlags    uint32
	Capabilities  uint32
	MaximalAccess uint32
}

const (
	ShareTypeDisk  uint8 = 0x01
	ShareTypePipe  uint8 = 0x02
	ShareTypePrint uint8 = 0x03
)

func (r *TreeConnectResponse) Append(dst []byte) []byte {
	dst = append(dst, 0x10, 0x00)
	dst = append(dst, r.ShareType, 0)
	var u32 [4]byte
	put32(u32[:], r.ShareFlags)
	dst = append(dst, u32[:]...)
	put32(u32[:], r.Capabilities)
	dst = append(dst, u32[:]...)
	put32(u32[:], r.MaximalAccess)
	dst = append(dst, u32[:]...)
	return dst
}

func (LogoffResponse) Append(dst []byte) []byte         { return appendSimpleResponse(dst) }
func (TreeDisconnectResponse) Append(dst []byte) []byte { return appendSimpleResponse(dst) }

type LogoffResponse struct{}
type TreeDisconnectResponse struct{}
