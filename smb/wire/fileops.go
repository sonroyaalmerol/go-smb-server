package wire

import (
	"encoding/binary"
	"fmt"
)

const createBody = 64

const (
	FileSupersede   uint32 = 0x00000000
	FileOpen        uint32 = 0x00000001
	FileCreate      uint32 = 0x00000002
	FileOpenIf      uint32 = 0x00000003
	FileOverwrite   uint32 = 0x00000004
	FileOverwriteIf uint32 = 0x00000005
)

const (
	FileDirectoryFile uint32 = 0x00000001
)

const (
	FileSuperseded  uint32 = 0x00000000
	FileOpened      uint32 = 0x00000001
	FileCreated     uint32 = 0x00000002
	FileOverwritten uint32 = 0x00000003
)

const (
	CloseFlagPostQueryAttrib uint16 = 0x0001
)

type CreateRequest struct {
	RequestedOplockLevel uint8
	DesiredAccess        uint32
	FileAttributes       uint32
	ShareAccess          uint32
	CreateDisposition    uint32
	CreateOptions        uint32
	Name                 []byte
}

func (r *CreateRequest) Parse(msg []byte) error {
	if len(msg) < createBody+57 {
		return fmt.Errorf("wire: create needs %d bytes, got %d", createBody+57, len(msg))
	}
	if ss := binary.LittleEndian.Uint16(msg[createBody : createBody+2]); ss != 57 {
		return fmt.Errorf("wire: create StructureSize = %d, want 57", ss)
	}
	r.RequestedOplockLevel = msg[createBody+3]
	r.DesiredAccess = binary.LittleEndian.Uint32(msg[createBody+24 : createBody+28])
	r.FileAttributes = binary.LittleEndian.Uint32(msg[createBody+28 : createBody+32])
	r.ShareAccess = binary.LittleEndian.Uint32(msg[createBody+32 : createBody+36])
	r.CreateDisposition = binary.LittleEndian.Uint32(msg[createBody+36 : createBody+40])
	r.CreateOptions = binary.LittleEndian.Uint32(msg[createBody+40 : createBody+44])
	nameOff := int(binary.LittleEndian.Uint16(msg[createBody+44 : createBody+46]))
	nameLen := int(binary.LittleEndian.Uint16(msg[createBody+46 : createBody+48]))
	if nameOff+nameLen > len(msg) {
		return fmt.Errorf("wire: create name out of range")
	}
	r.Name = msg[nameOff : nameOff+nameLen]
	return nil
}

type CreateResponse struct {
	OplockLevel    uint8
	Flags          uint8
	CreateAction   uint32
	CreationTime   uint64
	LastAccessTime uint64
	LastWriteTime  uint64
	ChangeTime     uint64
	AllocationSize uint64
	EndOfFile      uint64
	FileAttributes uint32
	FileId         [16]byte
}

func (r *CreateResponse) Append(dst []byte) []byte {
	const fixed = 89
	start := len(dst)
	out := append(dst, make([]byte, fixed)...)
	b := out[start:]
	put16(b[0:2], 89)
	b[2] = r.OplockLevel
	b[3] = r.Flags
	put32(b[4:8], r.CreateAction)
	put64(b[8:16], r.CreationTime)
	put64(b[16:24], r.LastAccessTime)
	put64(b[24:32], r.LastWriteTime)
	put64(b[32:40], r.ChangeTime)
	put64(b[40:48], r.AllocationSize)
	put64(b[48:56], r.EndOfFile)
	put32(b[56:60], r.FileAttributes)
	put32(b[60:64], 0)
	copy(b[64:80], r.FileId[:])
	put32(b[80:84], 0)
	put32(b[84:88], 0)
	return out
}

type CloseRequest struct {
	Flags  uint16
	FileId [16]byte
}

func (r *CloseRequest) Parse(msg []byte) error {
	if len(msg) < createBody+24 {
		return fmt.Errorf("wire: close needs %d bytes", createBody+24)
	}
	b := msg[createBody:]
	if ss := binary.LittleEndian.Uint16(b[0:2]); ss != 24 {
		return fmt.Errorf("wire: close StructureSize = %d, want 24", ss)
	}
	r.Flags = binary.LittleEndian.Uint16(b[2:4])
	copy(r.FileId[:], b[8:24])
	return nil
}

type CloseResponse struct {
	Flags          uint16
	CreationTime   uint64
	LastAccessTime uint64
	LastWriteTime  uint64
	ChangeTime     uint64
	AllocationSize uint64
	EndOfFile      uint64
	FileAttributes uint32
}

func (r *CloseResponse) Append(dst []byte) []byte {
	const fixed = 60
	start := len(dst)
	out := append(dst, make([]byte, fixed)...)
	b := out[start:]
	put16(b[0:2], 60)
	put16(b[2:4], r.Flags)
	put64(b[8:16], r.CreationTime)
	put64(b[16:24], r.LastAccessTime)
	put64(b[24:32], r.LastWriteTime)
	put64(b[32:40], r.ChangeTime)
	put64(b[40:48], r.AllocationSize)
	put64(b[48:56], r.EndOfFile)
	put32(b[56:60], r.FileAttributes)
	return out
}

type ReadRequest struct {
	Length uint32
	Offset uint64
	FileId [16]byte
}

func (r *ReadRequest) Parse(msg []byte) error {
	if len(msg) < createBody+49 {
		return fmt.Errorf("wire: read needs %d bytes", createBody+49)
	}
	b := msg[createBody:]
	if ss := binary.LittleEndian.Uint16(b[0:2]); ss != 49 {
		return fmt.Errorf("wire: read StructureSize = %d, want 49", ss)
	}
	r.Length = binary.LittleEndian.Uint32(b[4:8])
	r.Offset = binary.LittleEndian.Uint64(b[8:16])
	copy(r.FileId[:], b[16:32])
	return nil
}

func ReadResponseAppend(dst []byte, data []byte) []byte {
	const fixed = 16
	start := len(dst)
	out := append(dst, make([]byte, fixed)...)
	out = append(out, data...)
	b := out[start : start+fixed]
	put16(b[0:2], 17)
	b[2] = byte(start + fixed)
	b[3] = 0
	put32(b[4:8], uint32(len(data)))
	put32(b[8:12], 0)
	put32(b[12:16], 0)
	return out
}

type WriteRequest struct {
	Length uint32
	Offset uint64
	FileId [16]byte
	Data   []byte
}

func (r *WriteRequest) Parse(msg []byte) error {
	if len(msg) < createBody+49 {
		return fmt.Errorf("wire: write needs %d bytes", createBody+49)
	}
	b := msg[createBody:]
	if ss := binary.LittleEndian.Uint16(b[0:2]); ss != 49 {
		return fmt.Errorf("wire: write StructureSize = %d, want 49", ss)
	}
	dataOff := int(binary.LittleEndian.Uint16(b[2:4]))
	r.Length = binary.LittleEndian.Uint32(b[4:8])
	r.Offset = binary.LittleEndian.Uint64(b[8:16])
	copy(r.FileId[:], b[16:32])
	if dataOff+int(r.Length) > len(msg) {
		return fmt.Errorf("wire: write data out of range")
	}
	r.Data = msg[dataOff : dataOff+int(r.Length)]
	return nil
}

func WriteResponseAppend(dst []byte, count uint32) []byte {
	const fixed = 16
	start := len(dst)
	out := append(dst, make([]byte, fixed)...)
	b := out[start:]
	put16(b[0:2], 17)
	put32(b[4:8], count)
	return out
}

type QueryDirectoryRequest struct {
	FileInformationClass uint8
	Flags                uint8
	FileIndex            uint32
	FileId               [16]byte
	FileName             []byte
	OutputBufferLength   uint32
}

func (r *QueryDirectoryRequest) Parse(msg []byte) error {
	if len(msg) < createBody+33 {
		return fmt.Errorf("wire: query_directory needs %d bytes", createBody+33)
	}
	b := msg[createBody:]
	if ss := binary.LittleEndian.Uint16(b[0:2]); ss != 33 {
		return fmt.Errorf("wire: query_directory StructureSize = %d, want 33", ss)
	}
	r.FileInformationClass = b[2]
	r.Flags = b[3]
	r.FileIndex = binary.LittleEndian.Uint32(b[4:8])
	copy(r.FileId[:], b[8:24])
	nameOff := int(binary.LittleEndian.Uint16(b[24:26]))
	nameLen := int(binary.LittleEndian.Uint16(b[26:28]))
	r.OutputBufferLength = binary.LittleEndian.Uint32(b[28:32])
	if nameLen > 0 && nameOff+nameLen <= len(msg) {
		r.FileName = msg[nameOff : nameOff+nameLen]
	}
	return nil
}
