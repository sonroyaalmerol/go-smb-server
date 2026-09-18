package wire

import (
	"strings"
)

func UTF16FromBytes(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b) / 2)
	for i := 0; i+1 < len(b); i += 2 {
		r := rune(uint16(b[i]) | uint16(b[i+1])<<8)
		sb.WriteRune(r)
	}
	return sb.String()
}

func UTF16ToBytes(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		v := uint16(r)
		out = append(out, byte(v), byte(v>>8))
	}
	return out
}

const FileDirInfoMinSize = 64
const FileIdBothDirInfoMinSize = 104

// Directory information classes for QUERY_DIRECTORY (MS-FSCC section 2.4).
// Clients pick different ones -- the Linux client asks for a "full" class,
// Windows for an "id both" class -- and each has its own fixed-size prefix
// before the name, so a server must encode the one it was asked for.
const (
	FileDirectoryInformation       = 0x01
	FileFullDirectoryInformation   = 0x02
	FileBothDirectoryInformation   = 0x03
	FileNamesInformation           = 0x0C
	FileIdBothDirectoryInformation = 0x25
	FileIdFullDirectoryInformation = 0x26
)

const fileDirInfoFixed = 64
const fileIdBothDirInfoFixed = 104

// DirInfoFixedSize returns the size of the fixed part that precedes the file
// name for a directory information class, and whether the class is supported.
func DirInfoFixedSize(class uint8) (int, bool) {
	switch class {
	case FileDirectoryInformation:
		return 64, true
	case FileFullDirectoryInformation:
		return 68, true
	case FileBothDirectoryInformation:
		return 94, true
	case FileIdBothDirectoryInformation:
		return 104, true
	case FileIdFullDirectoryInformation:
		return 80, true
	case FileNamesInformation:
		return 12, true
	default:
		return 0, false
	}
}

// AppendDirInfo writes one directory entry in the requested class, padded to
// an 8-byte boundary, and returns the buffer and where the entry starts.
func AppendDirInfo(dst []byte, fi FileInfo, class uint8) (out []byte, entryStart int) {
	fixed, ok := DirInfoFixedSize(class)
	if !ok {
		return dst, -1
	}
	name := UTF16ToBytes(fi.Name)
	entryStart = len(dst)
	out = append(dst, make([]byte, fixed)...)
	out = append(out, name...)
	b := out[entryStart:]

	put32(b[0:4], 0) // NextEntryOffset, filled in by the caller
	put32(b[4:8], 0) // FileIndex
	if class == FileNamesInformation {
		put32(b[8:12], uint32(len(name)))
	} else {
		put64(b[8:16], fi.CreationTime)
		put64(b[16:24], fi.LastAccessTime)
		put64(b[24:32], fi.LastWriteTime)
		put64(b[32:40], fi.ChangeTime)
		put64(b[40:48], fi.EndOfFile)
		put64(b[48:56], fi.AllocationSize)
		put32(b[56:60], fi.FileAttributes)
		put32(b[60:64], uint32(len(name)))
		switch class {
		case FileFullDirectoryInformation, FileIdFullDirectoryInformation,
			FileBothDirectoryInformation, FileIdBothDirectoryInformation:
			put32(b[64:68], 0) // EaSize
		}
		switch class {
		case FileBothDirectoryInformation, FileIdBothDirectoryInformation:
			b[68] = 0 // ShortNameLength: no 8.3 alias
			b[69] = 0 // Reserved
		}
		switch class {
		case FileIdFullDirectoryInformation:
			put64(b[72:80], fi.FileId)
		case FileIdBothDirectoryInformation:
			put64(b[96:104], fi.FileId)
		}
	}

	if pad := (8 - len(out[entryStart:])%8) % 8; pad > 0 {
		out = append(out, make([]byte, pad)...)
	}
	return out, entryStart
}

type FileInfo struct {
	Name           string
	FileId         uint64
	EndOfFile      uint64
	AllocationSize uint64
	FileAttributes uint32
	CreationTime   uint64
	LastAccessTime uint64
	LastWriteTime  uint64
	ChangeTime     uint64
}

func AppendFileDirInfo(dst []byte, fi FileInfo) (out []byte, entryStart int) {
	name := UTF16ToBytes(fi.Name)
	entryStart = len(dst)
	out = append(dst, make([]byte, fileDirInfoFixed)...)
	out = append(out, name...)
	b := out[entryStart:]
	put32(b[0:4], 0)
	put32(b[4:8], 0)
	put64(b[8:16], fi.CreationTime)
	put64(b[16:24], fi.LastAccessTime)
	put64(b[24:32], fi.LastWriteTime)
	put64(b[32:40], fi.ChangeTime)
	put64(b[40:48], fi.EndOfFile)
	put64(b[48:56], fi.AllocationSize)
	put32(b[56:60], fi.FileAttributes)
	put32(b[60:64], uint32(len(name)))
	pad := (8 - len(out[entryStart:])%8) % 8
	if pad > 0 {
		out = append(out, make([]byte, pad)...)
	}
	return out, entryStart
}

func SetNextEntryOffset(buf []byte, entryStart, nextEntryStart int) {
	put32(buf[entryStart:entryStart+4], uint32(nextEntryStart-entryStart))
}

func AppendFileIdBothDirInfo(dst []byte, fi FileInfo) (out []byte, entryStart int) {
	name := UTF16ToBytes(fi.Name)
	entryStart = len(dst)
	out = append(dst, make([]byte, fileIdBothDirInfoFixed)...)
	out = append(out, name...)
	b := out[entryStart:]
	put32(b[0:4], 0)
	put32(b[4:8], 0)
	put64(b[8:16], fi.CreationTime)
	put64(b[16:24], fi.LastAccessTime)
	put64(b[24:32], fi.LastWriteTime)
	put64(b[32:40], fi.ChangeTime)
	put64(b[40:48], fi.EndOfFile)
	put64(b[48:56], fi.AllocationSize)
	put32(b[56:60], fi.FileAttributes)
	put32(b[60:64], uint32(len(name)))
	put32(b[64:68], 0)
	b[68] = 0
	b[69] = 0
	put64(b[96:104], 0)
	pad := (8 - len(out[entryStart:])%8) % 8
	if pad > 0 {
		out = append(out, make([]byte, pad)...)
	}
	return out, entryStart
}
