package encryption

import (
	"testing"
)

func BenchmarkSeal(b *testing.B) {
	c, err := NewAESCCM(make([]byte, 16))
	if err != nil {
		b.Fatal(err)
	}
	msg := make([]byte, 4096)
	b.SetBytes(int64(len(msg)))
	b.ReportAllocs()
	for b.Loop() {
		_, err := c.Seal(msg, 1)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOpen(b *testing.B) {
	c, err := NewAESCCM(make([]byte, 16))
	if err != nil {
		b.Fatal(err)
	}
	msg := make([]byte, 4096)
	sealed, err := c.Seal(msg, 1)
	if err != nil {
		b.Fatal(err)
	}
	buf := make([]byte, len(sealed))
	b.SetBytes(int64(len(msg)))
	b.ReportAllocs()
	for b.Loop() {
		copy(buf, sealed)
		_, err := c.Open(buf)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDeriveKey(b *testing.B) {
	key := make([]byte, 16)
	b.ReportAllocs()
	for b.Loop() {
		_ = DeriveServerEncryptionKey(key)
	}
}
