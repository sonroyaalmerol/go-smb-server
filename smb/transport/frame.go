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

	// A frame can arrive over several reads, and a read deadline can expire
	// partway through it. readHdr, hdrRead and bodyRead keep what has
	// arrived of the frame being read, so the next ReadMessage carries on
	// from there instead of reading the rest of the frame as a new header.
	readHdr  [HeaderLen]byte
	hdrRead  int
	bodyLen  int
	bodyRead int
}

func NewFramedConn(c net.Conn) *FramedConn {
	fc := &FramedConn{r: c, w: c, rawConn: c}
	readBuf := make([]byte, 0, 64<<10)
	fc.readBuf = readBuf[:0]
	return fc
}

// ReadMessage returns the next frame's payload. The returned slice is reused
// by the next call.
//
// An error from the connection, such as an expired read deadline, leaves a
// partly read frame in place: calling ReadMessage again resumes it. Callers
// that poll with short deadlines rely on this, since a large frame can take
// longer than the poll interval to arrive.
func (f *FramedConn) ReadMessage() ([]byte, error) {
	for f.hdrRead < HeaderLen {
		n, err := f.r.Read(f.readHdr[f.hdrRead:])
		f.hdrRead += n
		if f.hdrRead == HeaderLen {
			break
		}
		if err != nil {
			if errors.Is(err, io.EOF) && f.hdrRead > 0 {
				err = io.ErrUnexpectedEOF
			}
			return nil, fmt.Errorf("transport: read frame header: %w", err)
		}
	}
	if f.bodyLen == 0 && f.bodyRead == 0 {
		// The header has just been completed.
		if f.readHdr[0] != 0x00 {
			f.resetRead()
			return nil, fmt.Errorf("transport: unexpected frame type byte 0x%02x", f.readHdr[0])
		}
		n := int(readUint24(f.readHdr[1:]))
		if n == 0 {
			f.resetRead()
			f.readBuf = f.readBuf[:0]
			return f.readBuf, nil
		}
		if n > MaxMessageLen {
			f.resetRead()
			return nil, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, n)
		}
		if cap(f.readBuf) < n {
			f.readBuf = make([]byte, n)
		} else {
			f.readBuf = f.readBuf[:n]
		}
		f.bodyLen = n
	}
	for f.bodyRead < f.bodyLen {
		n, err := f.r.Read(f.readBuf[f.bodyRead:f.bodyLen])
		f.bodyRead += n
		if f.bodyRead == f.bodyLen {
			break
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return nil, fmt.Errorf("transport: read frame body: %w", err)
		}
	}
	msg := f.readBuf[:f.bodyLen]
	f.resetRead()
	return msg, nil
}

// resetRead forgets the frame just read, or one that cannot be read.
func (f *FramedConn) resetRead() {
	f.hdrRead, f.bodyLen, f.bodyRead = 0, 0, 0
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
