package wire

import "encoding/binary"

type ErrorResponse struct {
	ErrorContextCount uint8
	ErrorData         []byte
}

func (e *ErrorResponse) Append(dst []byte) []byte {
	dst = append(dst, 0x09, 0x00)
	dst = append(dst, e.ErrorContextCount, 0)
	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], uint32(len(e.ErrorData)))
	dst = append(dst, u32[:]...)
	return append(dst, e.ErrorData...)
}
