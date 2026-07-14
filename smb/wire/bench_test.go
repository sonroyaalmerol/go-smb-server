package wire

import (
	"testing"
)

func BenchmarkHeaderEncode(b *testing.B) {
	h := Header{
		ProtocolId:    SMB2ProtocolId,
		StructureSize: HeaderSize,
		Command:       CmdRead,
		Credit:        1,
		Flags:         FlagServerToRedir,
		MessageId:     42,
		SessionId:     1,
	}
	buf := make([]byte, 0, 256)
	b.ReportAllocs()
	for b.Loop() {
		buf = buf[:0]
		buf = h.Append(buf)
	}
}

func BenchmarkHeaderParse(b *testing.B) {
	h := Header{
		ProtocolId:    SMB2ProtocolId,
		StructureSize: HeaderSize,
		Command:       CmdRead,
	}
	buf := h.Append(nil)
	var parsed Header
	b.ReportAllocs()
	for b.Loop() {
		if err := parsed.Parse(buf); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReadResponseAlloc(b *testing.B) {
	dst := make([]byte, 0, 65536)
	b.SetBytes(4096)
	b.ReportAllocs()
	for b.Loop() {
		dst = dst[:0]
		dst = ReadResponseAlloc(dst, 4096)
	}
}

func BenchmarkUTF16FromBytes(b *testing.B) {
	encoded := UTF16ToBytes("hello-world-test.txt")
	b.ReportAllocs()
	for b.Loop() {
		_ = UTF16FromBytes(encoded)
	}
}

func BenchmarkUTF16ToBytes(b *testing.B) {
	s := "hello-world-test.txt"
	b.ReportAllocs()
	for b.Loop() {
		_ = UTF16ToBytes(s)
	}
}
