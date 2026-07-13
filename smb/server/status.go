package server

import (
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"os"

	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

var errEOF = io.EOF

func osErrToStatus(err error) uint32 {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return wire.StatusObjectNameNotFound
	case errors.Is(err, fs.ErrExist):
		return wire.StatusObjectNameCollision
	case errors.Is(err, fs.ErrPermission):
		return wire.StatusAccessDenied
	case errors.Is(err, os.ErrClosed):
		return wire.StatusInvalidHandle
	case errors.Is(err, io.EOF):
		return wire.StatusEndOfFile
	}
	return wire.StatusAccessDenied
}

func makeFileID(sessID uint64, treeID uint32, counter uint64) [16]byte {
	var fid [16]byte
	binary.LittleEndian.PutUint64(fid[0:8], sessID)
	binary.LittleEndian.PutUint32(fid[8:12], treeID)
	binary.LittleEndian.PutUint32(fid[12:16], uint32(counter))
	return fid
}
