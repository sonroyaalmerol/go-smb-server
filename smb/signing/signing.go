package signing

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

type Algorithm uint16

const (
	AlgoHMACSHA256 Algorithm = 0x0000
	AlgoAESCMAC    Algorithm = 0x0001
)

const headerSize = 64

func Sign(msg []byte, key []byte, algo Algorithm) error {
	if len(msg) < headerSize {
		return errors.New("signing: message shorter than header")
	}
	orig := [16]byte(msg[48:64])
	for i := 48; i < 64; i++ {
		msg[i] = 0
	}

	var sig [16]byte
	var err error
	switch algo {
	case AlgoHMACSHA256:
		mac := hmac.New(sha256.New, key)
		mac.Write(msg)
		copy(sig[:], mac.Sum(nil)[:16])
	case AlgoAESCMAC:
		sig, err = aesCMAC(msg, key)
	default:
		err = errors.New("signing: unsupported algorithm")
	}
	if err != nil {
		copy(msg[48:64], orig[:])
		return err
	}
	copy(msg[48:64], sig[:])
	return nil
}

func Verify(msg []byte, key []byte, algo Algorithm) (bool, error) {
	if len(msg) < headerSize {
		return false, errors.New("signing: message shorter than header")
	}
	want := [16]byte(msg[48:64])
	if err := Sign(msg, key, algo); err != nil {
		return false, err
	}
	return constantEqual(want[:], msg[48:64]), nil
}

func constantEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func aesCMAC(msg, key []byte) ([16]byte, error) {
	var out [16]byte
	if len(key) != 16 {
		return out, errors.New("signing: AES-128-CMAC requires a 16-byte key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return out, err
	}

	var l [16]byte
	block.Encrypt(l[:], l[:])
	k1 := cmacShift(l)
	k2 := cmacShift(k1)

	n := (len(msg) + 15) / 16
	if n == 0 {
		n = 1
	}

	var x [16]byte
	var y [16]byte
	for i := 0; i < n-1; i++ {
		blk := msg[i*16 : (i+1)*16]
		for j := range 16 {
			y[j] = x[j] ^ blk[j]
		}
		block.Encrypt(x[:], y[:])
	}

	var last [16]byte
	remaining := msg[(n-1)*16:]
	if len(remaining) == 16 {
		for j := range 16 {
			last[j] = remaining[j] ^ k1[j] ^ x[j]
		}
	} else {
		padded := cmacPad(remaining)
		for j := range 16 {
			last[j] = padded[j] ^ k2[j] ^ x[j]
		}
	}
	block.Encrypt(out[:], last[:])
	return out, nil
}

func cmacShift(k [16]byte) [16]byte {
	var out [16]byte
	carry := byte(0)
	for i := 15; i >= 0; i-- {
		out[i] = (k[i] << 1) | carry
		carry = (k[i] >> 7) & 1
	}
	if (k[0] >> 7) != 0 {
		out[15] ^= 0x87
	}
	return out
}

func cmacPad(b []byte) [16]byte {
	var out [16]byte
	copy(out[:], b)
	out[len(b)] = 0x80
	return out
}

// DeriveSigningKey computes the SMB 3.x signing key from the session key using
// the SP800-108 KDF in Counter Mode (MS-SMB2 section 3.1.4.2): HMAC-SHA256 with
// label "SMB2AESCMAC\0" and context "SmbSign\0", returning the first 16 bytes.
func DeriveSigningKey(sessionKey []byte) []byte {
	return kdfCounter(sessionKey, []byte("SMB2AESCMAC\x00"), []byte("SmbSign\x00"))
}

// kdfCounter implements NIST SP 800-108 5.1 in Counter Mode with h=256, r=32,
// L=128 (label/context per MS-SMB2 section 3.1.4.2).
func kdfCounter(ki, label, context []byte) []byte {
	mac := hmac.New(sha256.New, ki)
	mac.Write([]byte{0x00, 0x00, 0x00, 0x01}) // counter = 1
	mac.Write(label)
	mac.Write([]byte{0x00})
	mac.Write(context)
	mac.Write([]byte{0x00, 0x00, 0x00, 0x80}) // L = 128 bits
	return mac.Sum(nil)[:16]
}
