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

const (
	QueryDirRestartScans   uint8 = 0x01
	QueryDirReturnSingle   uint8 = 0x02
	QueryDirIndexSpecified uint8 = 0x04
	QueryDirReopen         uint8 = 0x10
)

// InfoType values (MS-SMB2 section 2.2.37).
const (
	InfoFile       uint8 = 0x01
	InfoFilesystem uint8 = 0x02
	InfoSecurity   uint8 = 0x03
	InfoQuota      uint8 = 0x04
)

// FileInfoClass values for queries (MS-FSCC section 2.4). Only the classes we
// implement are listed.
const (
	FileBasicInfoClass         uint8 = 0x04
	FileStandardInfoClass      uint8 = 0x05
	FileAllInformation         uint8 = 0x12
	FileNetworkOpenInformation uint8 = 0x22
)

// FileInfoClass values for sets (MS-FSCC section 2.4).
const (
	FileDispositionInformation uint8 = 0x0E
	FileEndOfFileInformation   uint8 = 0x14
	FileRenameInformation      uint8 = 0x0A
)

// FsInfoClass values for Filesystem queries (MS-FSCC section 2.5).
const (
	FileFsVolumeInformation     uint8 = 0x01
	FileFsSizeInformation       uint8 = 0x03
	FileFsDeviceInformation     uint8 = 0x04
	FileFsAttributeInformation  uint8 = 0x05
	FileFsFullSizeInformation   uint8 = 0x07
	FileFsSectorSizeInformation uint8 = 0x0B
)

// QueryInfoRequest is the SMB2 QUERY_INFO request body (section 2.2.37).
type QueryInfoRequest struct {
	InfoType           uint8
	FileInfoClass      uint8
	OutputBufferLength uint32
	AdditionalInfo     uint32
	Flags              uint32
	FileId             [16]byte
}

// Parse populates the request. msg is the full SMB2 message.
func (r *QueryInfoRequest) Parse(msg []byte) error {
	if len(msg) < createBody+41 {
		return fmt.Errorf("wire: query_info needs %d bytes", createBody+41)
	}
	b := msg[createBody:]
	if ss := binary.LittleEndian.Uint16(b[0:2]); ss != 41 {
		return fmt.Errorf("wire: query_info StructureSize = %d, want 41", ss)
	}
	r.InfoType = b[2]
	r.FileInfoClass = b[3]
	r.OutputBufferLength = binary.LittleEndian.Uint32(b[4:8])
	r.AdditionalInfo = binary.LittleEndian.Uint32(b[24:28])
	r.Flags = binary.LittleEndian.Uint32(b[28:32])
	copy(r.FileId[:], b[24:40])
	return nil
}

// SetInfoRequest is the SMB2 SET_INFO request body (section 2.2.39).
type SetInfoRequest struct {
	InfoType      uint8
	FileInfoClass uint8
	Buffer        []byte // aliases the message buffer
	FileId        [16]byte
}

// Parse populates the request. msg is the full SMB2 message.
func (r *SetInfoRequest) Parse(msg []byte) error {
	if len(msg) < createBody+33 {
		return fmt.Errorf("wire: set_info needs %d bytes", createBody+33)
	}
	b := msg[createBody:]
	if ss := binary.LittleEndian.Uint16(b[0:2]); ss != 33 {
		return fmt.Errorf("wire: set_info StructureSize = %d, want 33", ss)
	}
	r.InfoType = b[2]
	r.FileInfoClass = b[3]
	bufLen := int(binary.LittleEndian.Uint32(b[4:8]))
	bufOff := int(binary.LittleEndian.Uint16(b[8:10]))
	if bufOff+bufLen > len(msg) {
		return fmt.Errorf("wire: set_info buffer out of range")
	}
	r.Buffer = msg[bufOff : bufOff+bufLen]
	copy(r.FileId[:], b[16:32])
	return nil
}

// QueryInfoResponseAppend writes a QUERY_INFO response into dst. The fixed
// 8-byte body precedes the info buffer.
func QueryInfoResponseAppend(dst []byte, info []byte) []byte {
	const fixed = 8
	start := len(dst)
	out := append(dst, make([]byte, fixed)...)
	out = append(out, info...)
	b := out[start : start+fixed]
	put16(b[0:2], 9)                   // StructureSize
	put16(b[2:4], uint16(start+fixed)) // OutputBufferOffset (from header)
	put32(b[4:8], uint32(len(info)))
	return out
}

// SetInfoResponseAppend writes the SET_INFO response (8-byte fixed body).
func SetInfoResponseAppend(dst []byte) []byte {
	return append(dst, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // SS=33
}

// FlushResponseAppend writes the FLUSH response (4-byte fixed body).
func FlushResponseAppend(dst []byte) []byte {
	return append(dst, 0x04, 0x00, 0x00, 0x00) // SS=4
}

// --- FSCC info-class encoders (MS-FSCC section 2.4) ------------------------

// FileBasicInformation (MS-FSCC section 2.4.7): 40 bytes.
type FileBasicInformation struct {
	CreationTime   uint64
	LastAccessTime uint64
	LastWriteTime  uint64
	ChangeTime     uint64
	FileAttributes uint32
}

// Append encodes into dst (40 bytes).
func (f *FileBasicInformation) Append(dst []byte) []byte {
	out := append(dst, make([]byte, 40)...)
	o := out[len(dst):]
	put64(o[0:8], f.CreationTime)
	put64(o[8:16], f.LastAccessTime)
	put64(o[16:24], f.LastWriteTime)
	put64(o[24:32], f.ChangeTime)
	put32(o[32:36], f.FileAttributes)
	return out
}

// Parse reads a FileBasicInformation from b (sets use the same layout).
func (f *FileBasicInformation) Parse(b []byte) error {
	if len(b) < 40 {
		return fmt.Errorf("wire: FileBasicInformation needs 40 bytes")
	}
	f.CreationTime = binary.LittleEndian.Uint64(b[0:8])
	f.LastAccessTime = binary.LittleEndian.Uint64(b[8:16])
	f.LastWriteTime = binary.LittleEndian.Uint64(b[16:24])
	f.ChangeTime = binary.LittleEndian.Uint64(b[24:32])
	f.FileAttributes = binary.LittleEndian.Uint32(b[32:36])
	return nil
}

// FileStandardInformation (MS-FSCC section 2.4.36): 24 bytes.
type FileStandardInformation struct {
	AllocationSize uint64
	EndOfFile      uint64
	NumberOfLinks  uint32
	DeletePending  uint8
	Directory      uint8
}

// Append encodes into dst (24 bytes).
func (f *FileStandardInformation) Append(dst []byte) []byte {
	out := append(dst, make([]byte, 24)...)
	o := out[len(dst):]
	put64(o[0:8], f.AllocationSize)
	put64(o[8:16], f.EndOfFile)
	put32(o[16:20], f.NumberOfLinks)
	o[20] = f.DeletePending
	o[21] = f.Directory
	return out
}

// FileAllInformationAppend writes a minimal FileAllInformation (Basic +
// Standard + empty Access/Mode/Position/EA) suitable for common clients.
func FileAllInformationAppend(dst []byte, basic FileBasicInformation, standard FileStandardInformation) []byte {
	start := len(dst)
	out := basic.Append(dst)
	out = standard.Append(out)
	// AccessInformation (4) + ModeInformation (4) + PositionInformation (8) +
	// AlignmentRequirement (4) ... we emit zeros for these required-but-empty
	// members; many clients ignore them.
	out = append(out, make([]byte, 4+4+8+4)...)
	_ = start
	return out
}

// --- LOCK and IOCTL (sections 2.2.26 / 2.2.31) -----------------------------

// LOCK element flags (MS-SMB2 section 2.2.26.1).
const (
	LockFlagSharedLock      uint32 = 0x00000001
	LockFlagExclusiveLock   uint32 = 0x00000002
	LockFlagUnlock          uint32 = 0x00000004
	LockFlagFailImmediately uint32 = 0x00000010
)

// LockElement is one SMB2_LOCK_ELEMENT (section 2.2.26.1).
type LockElement struct {
	Offset uint64
	Length uint64
	Flags  uint32
}

// LockRequest is the SMB2 LOCK request body (section 2.2.26).
type LockRequest struct {
	Locks  []LockElement
	FileId [16]byte
}

// Parse populates the request. msg is the full SMB2 message.
func (r *LockRequest) Parse(msg []byte) error {
	if len(msg) < createBody+48 {
		return fmt.Errorf("wire: lock needs %d bytes", createBody+48)
	}
	b := msg[createBody:]
	if ss := binary.LittleEndian.Uint16(b[0:2]); ss != 48 {
		return fmt.Errorf("wire: lock StructureSize = %d, want 48", ss)
	}
	count := int(binary.LittleEndian.Uint16(b[2:4]))
	copy(r.FileId[:], b[8:24])
	end := 48 + count*24
	if createBody+end > len(msg) {
		return fmt.Errorf("wire: lock: %d locks exceed body", count)
	}
	r.Locks = make([]LockElement, count)
	for i := range r.Locks {
		off := 48 + i*24
		r.Locks[i].Offset = binary.LittleEndian.Uint64(b[off : off+8])
		r.Locks[i].Length = binary.LittleEndian.Uint64(b[off+8 : off+16])
		r.Locks[i].Flags = binary.LittleEndian.Uint32(b[off+16 : off+20])
	}
	return nil
}

// LockResponseAppend writes the LOCK response (4-byte body).
func LockResponseAppend(dst []byte) []byte {
	return append(dst, 0x04, 0x00, 0x00, 0x00) // SS=4
}

// IoctlRequest is the SMB2 IOCTL request body (section 2.2.31).
type IoctlRequest struct {
	CtlCode           uint32
	FileId            [16]byte
	Input             []byte // aliases the message buffer
	MaxOutputResponse uint32
	Flags             uint32
}

// Parse populates the request. msg is the full SMB2 message.
func (r *IoctlRequest) Parse(msg []byte) error {
	if len(msg) < createBody+57 {
		return fmt.Errorf("wire: ioctl needs %d bytes", createBody+57)
	}
	b := msg[createBody:]
	if ss := binary.LittleEndian.Uint16(b[0:2]); ss != 57 {
		return fmt.Errorf("wire: ioctl StructureSize = %d, want 57", ss)
	}
	r.CtlCode = binary.LittleEndian.Uint32(b[4:8])
	copy(r.FileId[:], b[8:24])
	inOff := int(binary.LittleEndian.Uint32(b[24:28]))
	inLen := int(binary.LittleEndian.Uint32(b[28:32]))
	r.MaxOutputResponse = binary.LittleEndian.Uint32(b[40:44])
	r.Flags = binary.LittleEndian.Uint32(b[44:48])
	if inLen > 0 && inOff+inLen <= len(msg) {
		r.Input = msg[inOff : inOff+inLen]
	}
	return nil
}

// IoctlResponseAppend writes an IOCTL response carrying out as the output buffer.
func IoctlResponseAppend(dst []byte, out []byte) []byte {
	const fixed = 48
	start := len(dst)
	total := fixed + len(out)
	out2 := append(dst, make([]byte, total)...)
	b := out2[start:]
	put16(b[0:2], 49) // StructureSize
	// Input offset/count: zero (no input echoed).
	outOff := uint32(start + fixed)
	put32(b[24:28], outOff) // OutputOffset (from header)
	put32(b[28:32], uint32(len(out)))
	copy(b[fixed:], out)
	return out2
}

// FSCTL control codes (MS-SMB2 section 2.2.31 / MS-FSCC section 2.3).
const (
	FSCTLDfsGetReferrals           uint32 = 0x00060194
	FSCTLSrvCopychunk              uint32 = 0x001440F2
	FSCTLSrvEnumerateSnapshots     uint32 = 0x00144064
	FSCTLSrvRequestResumeKey       uint32 = 0x00140078
	FSCTLQueryNetworkInterfaceInfo uint32 = 0x001401FC
	FSCTLValidateNegotiateInfo     uint32 = 0x00140204
	FSCTLLMRRequestResiliency      uint32 = 0x001401D4
)
