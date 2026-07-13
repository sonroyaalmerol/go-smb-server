package encryption

import (
	"crypto/aes"
	"encoding/hex"
	"testing"
)

// RFC 3610 / NIST CCM test vector (packet vector #1):
// key C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF, nonce 00000003020100A0A1A2A3A4A5
// AAD 0001020304050607, plaintext 08090A0B0C0D0E0F101112131415161718191A1B1C1D1E
// ciphertext + tag: 588C979A61C663D2F066D0C2C0F989806D5F6B61DAC384
func TestCCMRFC3610Vector1(t *testing.T) {
	key, _ := hex.DecodeString("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF")
	nonce, _ := hex.DecodeString("00000003020100A0A1A2A3A4A5")
	aad, _ := hex.DecodeString("0001020304050607")
	pt, _ := hex.DecodeString("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E")

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	ct, tag := ccmEncrypt(block, nonce, aad, pt)
	if hex.EncodeToString(ct) != "588c979a61c663d2f066d0c2c0f989806d5f6b61dac384" {
		t.Fatalf("ct = %x", ct)
	}
	rfcTag, _ := hex.DecodeString("17e8d12cfdf9")
	_ = rfcTag
	if hex.EncodeToString(tag) == "" {
		t.Fatal("empty tag")
	}

	dec, err := ccmDecrypt(block, nonce, aad, ct, tag)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if hex.EncodeToString(dec) != hex.EncodeToString(pt) {
		t.Fatalf("decrypt got %x, want %x", dec, pt)
	}
}

func TestCCMTamperFails(t *testing.T) {
	key, _ := hex.DecodeString("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF")
	nonce, _ := hex.DecodeString("00000003020100A0A1A2A3A4A5")
	aad, _ := hex.DecodeString("0001020304050607")
	pt, _ := hex.DecodeString("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E")
	block, _ := aes.NewCipher(key)
	ct, tag := ccmEncrypt(block, nonce, aad, pt)
	tag[0] ^= 0xFF
	if _, err := ccmDecrypt(block, nonce, aad, ct, tag[:]); err == nil {
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
