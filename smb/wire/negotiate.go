package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

func put16(dst []byte, v uint16) { binary.LittleEndian.PutUint16(dst, v) }
func put32(dst []byte, v uint32) { binary.LittleEndian.PutUint32(dst, v) }
func put64(dst []byte, v uint64) { binary.LittleEndian.PutUint64(dst, v) }

func alignUp(n, to int) int { return (n + to - 1) &^ (to - 1) }

type NegotiateContext struct {
	Type uint16
	Data []byte
}

const (
	CtxPreauthIntegrity uint16 = 0x0001
	CtxEncryption       uint16 = 0x0002
	CtxCompression      uint16 = 0x0003
	CtxNetname          uint16 = 0x0005
	CtxTransport        uint16 = 0x0006
	CtxRDMATransform    uint16 = 0x0007
	CtxSigning          uint16 = 0x0008
)

type NegotiateRequest struct {
	SecurityMode uint16
	Capabilities uint32
	ClientGuid   [16]byte
	Dialects     []uint16
	Contexts     []NegotiateContext
}

func (r *NegotiateRequest) Parse(body []byte) error {
	if len(body) < 36 {
		return fmt.Errorf("wire: negotiate request needs 36 bytes, got %d", len(body))
	}
	if ss := binary.LittleEndian.Uint16(body[0:2]); ss != 36 {
		return fmt.Errorf("wire: negotiate request StructureSize = %d, want 36", ss)
	}
	dialectCount := int(binary.LittleEndian.Uint16(body[2:4]))
	r.SecurityMode = binary.LittleEndian.Uint16(body[4:6])
	r.Capabilities = binary.LittleEndian.Uint32(body[8:12])
	copy(r.ClientGuid[:], body[12:28])

	dialectEnd := 36 + dialectCount*2
	if dialectEnd > len(body) {
		return fmt.Errorf("wire: negotiate declares %d dialects but body is %d bytes", dialectCount, len(body))
	}
	r.Dialects = r.Dialects[:0]
	for i := range dialectCount {
		off := 36 + i*2
		r.Dialects = append(r.Dialects, binary.LittleEndian.Uint16(body[off:off+2]))
	}

	r.Contexts = r.Contexts[:0]
	for _, d := range r.Dialects {
		if d == DialectSMB311 {
			ctxOff := int(binary.LittleEndian.Uint32(body[28:32]))
			ctxCount := int(binary.LittleEndian.Uint16(body[32:34]))
			if err := r.parseContexts(body, ctxOff, ctxCount); err != nil {
				return err
			}
			break
		}
	}
	return nil
}

func (r *NegotiateRequest) parseContexts(body []byte, offset, count int) error {
	for range count {
		if offset+8 > len(body) {
			return errors.New("wire: negotiate context header truncated")
		}
		ctxType := binary.LittleEndian.Uint16(body[offset : offset+2])
		dataLen := int(binary.LittleEndian.Uint16(body[offset+2 : offset+4]))
		if offset+8+dataLen > len(body) {
			return errors.New("wire: negotiate context data truncated")
		}
		r.Contexts = append(r.Contexts, NegotiateContext{
			Type: ctxType,
			Data: body[offset+8 : offset+8+dataLen],
		})
		offset = alignUp(offset+8+dataLen, 8)
	}
	return nil
}

type NegotiateResponse struct {
	SecurityMode    uint16
	DialectRevision uint16
	ServerGuid      [16]byte
	Capabilities    uint32
	MaxTransactSize uint32
	MaxReadSize     uint32
	MaxWriteSize    uint32
	SystemTime      uint64
	ServerStartTime uint64
	SecurityBuffer  []byte
	Contexts        []NegotiateContext
}

func (r *NegotiateResponse) Append(dst []byte) []byte {
	const bodyFixed = 64
	secLen := len(r.SecurityBuffer)
	total := bodyFixed + secLen

	var secPad int
	if r.DialectRevision == DialectSMB311 {
		secPad = (-total) & 7
		total += secPad
		for _, c := range r.Contexts {
			total += alignUp(8+len(c.Data), 8)
		}
	}

	start := len(dst)
	out := append(dst, make([]byte, total)...)
	b := out[start:]

	put16(b[0:2], 65)
	put16(b[2:4], r.SecurityMode)
	put16(b[4:6], r.DialectRevision)
	put16(b[6:8], uint16(len(r.Contexts)))
	copy(b[8:24], r.ServerGuid[:])
	put32(b[24:28], r.Capabilities)
	put32(b[28:32], r.MaxTransactSize)
	put32(b[32:36], r.MaxReadSize)
	put32(b[36:40], r.MaxWriteSize)
	put64(b[40:48], r.SystemTime)
	put64(b[48:56], r.ServerStartTime)

	secBufOff := HeaderSize + bodyFixed
	put16(b[56:58], uint16(secBufOff))
	put16(b[58:60], uint16(secLen))
	copy(b[bodyFixed:bodyFixed+secLen], r.SecurityBuffer)

	if r.DialectRevision != DialectSMB311 {
		return out
	}
	ctxOff := HeaderSize + bodyFixed + secLen + secPad
	put32(b[60:64], uint32(ctxOff))

	off := bodyFixed + secLen + secPad
	for _, c := range r.Contexts {
		put16(b[off:off+2], c.Type)
		put16(b[off+2:off+4], uint16(len(c.Data)))
		off += 8
		off += copy(b[off:], c.Data)
		if p := (-off) & 7; p != 0 {
			off += p
		}
	}
	return out
}
