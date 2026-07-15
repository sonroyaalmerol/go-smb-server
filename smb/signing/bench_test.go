package signing

import (
	"testing"
)

func BenchmarkSign(b *testing.B) {
	s, err := NewSigner(make([]byte, 16))
	if err != nil {
		b.Fatal(err)
	}
	msg := make([]byte, 256)
	msg[0] = 0xFE
	b.SetBytes(int64(len(msg)))
	b.ReportAllocs()
	for b.Loop() {
		msg[48] = 0
		msg[49] = 0
		if err := s.Sign(msg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	s, err := NewSigner(make([]byte, 16))
	if err != nil {
		b.Fatal(err)
	}
	msg := make([]byte, 256)
	msg[0] = 0xFE
	_ = s.Sign(msg)
	b.SetBytes(int64(len(msg)))
	b.ReportAllocs()
	for b.Loop() {
		ok, err := s.Verify(msg)
		if err != nil || !ok {
			b.Fatal("verify failed")
		}
	}
}

func BenchmarkDeriveSigningKey(b *testing.B) {
	key := make([]byte, 16)
	b.ReportAllocs()
	for b.Loop() {
		_ = DeriveSigningKey(key)
	}
}
