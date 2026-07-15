package transport

import (
	"errors"
	"fmt"
	"io"
	"net"
)

const (
	HeaderLen     = 4
	MaxMessageLen = 16 << 20
)

var ErrFrameTooLarge = errors.New("transport: frame exceeds maximum length")

func readUint24(b []byte) uint32 {
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
}

func writeUint24(b []byte, v uint32) {
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
}

type FramedConn struct {
	r       io.Reader
	w       io.Writer
	rawConn net.Conn
	readBuf []byte
	hdrBuf  [HeaderLen]byte
}

func NewFramedConn(c net.Conn) *FramedConn {
	fc := &FramedConn{r: c, w: c, rawConn: c}
	readBuf := make([]byte, 0, 64<<10)
	fc.readBuf = readBuf[:0]
	return fc
}

func (f *FramedConn) ReadMessage() ([]byte, error) {
	if _, err := io.ReadFull(f.r, f.hdrBuf[:]); err != nil {
		return nil, fmt.Errorf("transport: read frame header: %w", err)
	}
	if f.hdrBuf[0] != 0x00 {
		return nil, fmt.Errorf("transport: unexpected frame type byte 0x%02x", f.hdrBuf[0])
	}
	n := int(readUint24(f.hdrBuf[1:]))
	if n == 0 {
		f.readBuf = f.readBuf[:0]
		return f.readBuf, nil
	}
	if n > MaxMessageLen {
		return nil, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, n)
	}
	if cap(f.readBuf) < n {
		f.readBuf = make([]byte, n)
	} else {
		f.readBuf = f.readBuf[:n]
	}
	if _, err := io.ReadFull(f.r, f.readBuf); err != nil {
		return nil, fmt.Errorf("transport: read frame body: %w", err)
	}
	return f.readBuf, nil
}

func (f *FramedConn) WriteMessage(payload []byte) error {
	if len(payload) == 0 {
		return errors.New("transport: cannot write empty frame")
	}
	if uint32(len(payload)) > MaxMessageLen {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, len(payload))
	}
	f.hdrBuf[0] = 0x00
	writeUint24(f.hdrBuf[1:], uint32(len(payload)))

	if _, err := f.w.Write(f.hdrBuf[:]); err != nil {
		return fmt.Errorf("transport: write frame header: %w", err)
	}
	if _, err := f.w.Write(payload); err != nil {
		return fmt.Errorf("transport: write frame body: %w", err)
	}
	return nil
}

func (f *FramedConn) Underlying() net.Conn { return f.rawConn }
