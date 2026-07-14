package encryption

import (
	"crypto/aes"
	"encoding/hex"
	"testing"
)

func TestCCMRFC3610Vector1(t *testing.T) {
	key, _ := hex.DecodeString("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF")
	nonce, _ := hex.DecodeString("00000003020100A0A1A2A3A4A5")
	aad, _ := hex.DecodeString("0001020304050607")
	pt, _ := hex.DecodeString("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E")

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	data := make([]byte, len(pt))
	copy(data, pt)
	tag := ccmEncryptInPlace(block, nonce, aad, data)
	if hex.EncodeToString(data) != "588c979a61c663d2f066d0c2c0f989806d5f6b61dac384" {
		t.Fatalf("ct = %x", data)
	}

	if err := ccmDecryptInPlace(block, nonce, aad, data, tag[:]); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if hex.EncodeToString(data) != hex.EncodeToString(pt) {
		t.Fatalf("decrypt got %x, want %x", data, pt)
	}
}

func TestCCMTamperFails(t *testing.T) {
	key, _ := hex.DecodeString("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF")
	nonce, _ := hex.DecodeString("00000003020100A0A1A2A3A4A5")
	aad, _ := hex.DecodeString("0001020304050607")
	pt, _ := hex.DecodeString("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E")
	block, _ := aes.NewCipher(key)

	data := make([]byte, len(pt))
	copy(data, pt)
	tag := ccmEncryptInPlace(block, nonce, aad, data)
	tag[0] ^= 0xFF
	if err := ccmDecryptInPlace(block, nonce, aad, data, tag[:]); err == nil {
		t.Fatal("decrypt accepted a tampered tag")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	c, err := NewAESCCM(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("encrypted SMB message payload")
	sealed, err := c.Seal(msg, 0x1234)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := c.Open(sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if string(opened) != string(msg) {
		t.Fatalf("roundtrip = %q, want %q", opened, msg)
	}
}
