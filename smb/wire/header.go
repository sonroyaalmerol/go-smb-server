package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type Header struct {
	ProtocolId    [4]byte
	StructureSize uint16
	CreditCharge  uint16
	Status        uint32
	Command       uint16
	Credit        uint16
	Flags         uint32
	NextCommand   uint32
	MessageId     uint64
	AsyncId       uint64
	TreeId        uint32
	SessionId     uint64
	Signature     [16]byte
}

func NewHeader(cmd uint16) Header {
	return Header{
		ProtocolId:    SMB2ProtocolId,
		StructureSize: HeaderSize,
		Command:       cmd,
	}
}

func (h *Header) Append(dst []byte) []byte {
	start := len(dst)
	dst = append(dst, make([]byte, HeaderSize)...)
	h.EncodeAt(dst[start:])
	return dst
}

func (h *Header) EncodeAt(dst []byte) {
	dst[0], dst[1], dst[2], dst[3] = SMB2ProtocolId[0], SMB2ProtocolId[1], SMB2ProtocolId[2], SMB2ProtocolId[3]
	put16(dst[4:6], HeaderSize)
	put16(dst[6:8], h.CreditCharge)
	put32(dst[8:12], h.Status)
	put16(dst[12:14], h.Command)
	put16(dst[14:16], h.Credit)
	put32(dst[16:20], h.Flags)
	put32(dst[20:24], h.NextCommand)
	put64(dst[24:32], h.MessageId)
	if h.Flags&FlagAsyncCommand != 0 {
		put64(dst[32:40], h.AsyncId)
	} else {
		put32(dst[32:36], 0)
		put32(dst[36:40], h.TreeId)
	}
	put64(dst[40:48], h.SessionId)
	copy(dst[48:64], h.Signature[:])
}

func (h *Header) Parse(b []byte) error {
	if len(b) < HeaderSize {
		return fmt.Errorf("wire: header needs %d bytes, got %d", HeaderSize, len(b))
	}
	if [4]byte{b[0], b[1], b[2], b[3]} != SMB2ProtocolId {
		return errors.New("wire: bad protocol id (not an SMB2 packet)")
	}
	h.ProtocolId = SMB2ProtocolId
	h.StructureSize = binary.LittleEndian.Uint16(b[4:6])
	h.CreditCharge = binary.LittleEndian.Uint16(b[6:8])
	h.Status = binary.LittleEndian.Uint32(b[8:12])
	h.Command = binary.LittleEndian.Uint16(b[12:14])
	h.Credit = binary.LittleEndian.Uint16(b[14:16])
	h.Flags = binary.LittleEndian.Uint32(b[16:20])
	h.NextCommand = binary.LittleEndian.Uint32(b[20:24])
	h.MessageId = binary.LittleEndian.Uint64(b[24:32])
	if h.Flags&FlagAsyncCommand != 0 {
		h.AsyncId = binary.LittleEndian.Uint64(b[32:40])
	} else {
		h.TreeId = binary.LittleEndian.Uint32(b[36:40])
	}
	h.SessionId = binary.LittleEndian.Uint64(b[40:48])
	copy(h.Signature[:], b[48:64])
	return nil
}

func (h Header) IsResponse() bool { return h.Flags&FlagServerToRedir != 0 }
