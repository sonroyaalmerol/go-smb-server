package vfs

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"iter"
	"strings"
	"sync"
	"time"
)

type PipeHandler func(rpcData []byte) []byte

type PipeBackend struct {
	mu       sync.Mutex
	handlers map[string]PipeHandler
}

func NewPipeBackend() *PipeBackend {
	return &PipeBackend{
		handlers: make(map[string]PipeHandler),
	}
}

func (b *PipeBackend) Register(name string, h PipeHandler) {
	b.mu.Lock()
	b.handlers[name] = h
	b.mu.Unlock()
}

func (b *PipeBackend) Open(ctx context.Context, opts OpenOptions) (Handle, error) {
	b.mu.Lock()
	path := opts.Path
	path = strings.TrimPrefix(path, "\\")
	path = strings.TrimPrefix(path, "PIPE\\")
	handler, ok := b.handlers[path]
	b.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("vfs: pipe %q not found", path)
	}
	h := &pipeHandle{
		handler: handler,
		name:    path,
		info: FileInfo{
			Name:         path,
			CreationTime: time.Now(),
			LastWrite:    time.Now(),
			LastAccess:   time.Now(),
			ChangeTime:   time.Now(),
		},
	}
	h.cond = sync.NewCond(&h.mu)
	return h, nil
}

type pipeHandle struct {
	handler PipeHandler
	name    string
	info    FileInfo

	mu       sync.Mutex
	cond     *sync.Cond
	writeBuf []byte
	hasWrite bool
	readBuf  []byte
	readPos  int
	closed   bool
}

func (h *pipeHandle) Read(ctx context.Context, offset int64, p []byte) (int, error) {
	h.mu.Lock()
	for !h.hasWrite && h.readPos >= len(h.readBuf) && !h.closed {
		h.cond.Wait()
	}
	if h.closed {
		h.mu.Unlock()
		return 0, io.EOF
	}

	var data []byte
	switch {
	case h.readPos >= len(h.readBuf) && h.hasWrite:
		data = h.handler(h.writeBuf)
		h.readBuf = data
		h.readPos = 0
		h.hasWrite = false
		h.writeBuf = nil
	case h.readPos < len(h.readBuf):
		data = h.readBuf
	}
	h.mu.Unlock()

	if len(data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, data[h.readPos:])
	h.mu.Lock()
	h.readPos += n
	h.mu.Unlock()
	return n, nil
}

func (h *pipeHandle) Write(ctx context.Context, offset int64, p []byte) (int, error) {
	h.mu.Lock()
	h.writeBuf = append(h.writeBuf[:0], p...)
	h.hasWrite = true
	h.mu.Unlock()
	h.cond.Broadcast()
	return len(p), nil
}

func (h *pipeHandle) Close(ctx context.Context) error {
	h.mu.Lock()
	h.closed = true
	h.hasWrite = false
	h.writeBuf = nil
	h.readBuf = nil
	h.mu.Unlock()
	h.cond.Broadcast()
	return nil
}

func (h *pipeHandle) Stat(ctx context.Context) (FileInfo, error) { return h.info, nil }

func (h *pipeHandle) Enumerate(ctx context.Context, pattern string) iter.Seq2[FileInfo, error] {
	return func(yield func(FileInfo, error) bool) {}
}

func (h *pipeHandle) ProcessPipe(_ context.Context, input []byte) []byte {
	h.mu.Lock()
	h.writeBuf = append(h.writeBuf[:0], input...)
	result := h.handler(h.writeBuf)
	h.mu.Unlock()
	return result
}

func toUTF16LE(s string) []byte {
	r := []rune(s)
	out := make([]byte, len(r)*2)
	for i, c := range r {
		v := uint16(c)
		out[i*2] = byte(v)
		out[i*2+1] = byte(v >> 8)
	}
	return out
}

func putLE32(b []byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}

func putLE16(b []byte, v uint16) {
	b[0], b[1] = byte(v), byte(v>>8)
}

var srvsvcUUID = [16]byte{
	0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01,
	0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88,
}

const (
	srvsvcShareTypeDisk  uint32 = 0
	srvsvcShareTypePrint uint32 = 1
	srvsvcShareTypeIPC   uint32 = 3
)

func SrvsvcHandler(shares [][2]string) PipeHandler {
	return func(rpcData []byte) []byte {
		return handleSrvsvcRPC(rpcData, shares)
	}
}

func handleSrvsvcRPC(body []byte, shares [][2]string) []byte {
	if len(body) < 16 {
		return buildNackResponse(0)
	}
	pduType := body[2]
	callID := binary.LittleEndian.Uint32(body[12:16])

	switch pduType {
	case 0x0B:
		return buildBindAck(callID)
	case 0x00:
		opnum := uint16(0)
		if len(body) >= 24 {
			opnum = binary.LittleEndian.Uint16(body[22:24])
		}
		if opnum == 15 {
			stub := buildNetrShareEnumResponse(shares)
			return buildResponsePDU(callID, stub)
		}
		return buildNackResponse(callID)
	default:
		return buildNackResponse(callID)
	}
}

func buildBindAck(callID uint32) []byte {
	b := make([]byte, 56)
	b[0] = 5
	b[1] = 0
	b[2] = 0x0C
	b[3] = 0x03
	b[4], b[5], b[6], b[7] = 0x10, 0x00, 0x00, 0x00
	putLE16(b[8:10], 56)
	putLE16(b[10:12], 0)
	putLE32(b[12:16], callID)
	putLE16(b[16:18], 5840)
	putLE16(b[18:20], 5840)
	putLE32(b[20:24], 0x000053b6)

	putLE16(b[24:26], 0)
	putLE16(b[26:28], 40)

	putLE32(b[28:32], 1)

	b[32] = 0
	b[33] = 0
	b[34] = 0
	b[35] = 0

	tsUUID := [16]byte{
		0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
		0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
	}
	copy(b[36:52], tsUUID[:])
	putLE32(b[52:56], 2)

	return b
}

func buildResponsePDU(callID uint32, stub []byte) []byte {
	stubLen := len(stub)
	pad := (4 - stubLen) & 3
	total := 24 + stubLen + pad
	b := make([]byte, total)
	b[0] = 5
	b[1] = 0
	b[2] = 0x02
	b[3] = 0x03
	b[4], b[5], b[6], b[7] = 0x10, 0x00, 0x00, 0x00
	putLE16(b[8:10], uint16(total))
	putLE16(b[10:12], 0)
	putLE32(b[12:16], callID)
	putLE32(b[16:20], uint32(stubLen))
	putLE16(b[20:22], 0)
	putLE16(b[22:24], 0)
	copy(b[24:], stub)
	return b
}

func buildNackResponse(callID uint32) []byte {
	b := make([]byte, 32)
	b[0] = 5
	b[1] = 0
	b[2] = 0x03
	b[3] = 0x03
	b[4], b[5], b[6], b[7] = 0x10, 0x00, 0x00, 0x00
	putLE16(b[8:10], 32)
	putLE16(b[10:12], 0)
	putLE32(b[12:16], callID)
	putLE32(b[16:20], 20)
	putLE16(b[20:22], 0)
	putLE16(b[22:24], 0)
	putLE32(b[24:28], 0x000006E4)
	return b
}

func buildNetrShareEnumResponse(shares [][2]string) []byte {
	var buf []byte
	refID := uint32(0x00020000)
	nextRef := func() uint32 { r := refID; refID += 4; return r }

	addU32 := func(v uint32) {
		var tmp [4]byte
		putLE32(tmp[:], v)
		buf = append(buf, tmp[:]...)
	}
	addStr := func(s string) {
		cnt := uint32(len([]rune(s)) + 1)
		addU32(cnt)
		addU32(0)
		addU32(cnt)
		u := toUTF16LE(s)
		buf = append(buf, u...)
		buf = append(buf, 0x00, 0x00)
		for len(buf)&3 != 0 {
			buf = append(buf, 0)
		}
	}

	n := uint32(len(shares))

	addU32(1)
	addU32(1)
	ctrRef := nextRef()
	addU32(ctrRef)

	addU32(0)
	addU32(0)

	addU32(n)
	bufRef := nextRef()
	addU32(bufRef)

	addU32(n)
	for range shares {
		addU32(nextRef())
		addU32(srvsvcShareTypeDisk)
		addU32(nextRef())
	}

	for _, sh := range shares {
		addStr(sh[0])
		addStr(sh[1])
	}

	addU32(n)

	return buf
}
