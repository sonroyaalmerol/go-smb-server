package signing

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

const headerSize = 64

var errShort = errors.New("signing: message shorter than header")

type Signer struct {
	aesBlock interface{ Encrypt(dst, src []byte) }
	cmacK1   [16]byte
	cmacK2   [16]byte
}

func NewSigner(key []byte) (*Signer, error) {
	if len(key) != 16 {
		return nil, errors.New("signing: AES-128-CMAC requires a 16-byte key")
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	s := &Signer{aesBlock: blk}
	var l [16]byte
	blk.Encrypt(l[:], l[:])
	s.cmacK1 = cmacShift(l)
	s.cmacK2 = cmacShift(s.cmacK1)
	return s, nil
}

func (s *Signer) Sign(msg []byte) error {
	if len(msg) < headerSize {
		return errShort
	}
	for i := 48; i < 64; i++ {
		msg[i] = 0
	}
	sig := s.cmac(msg)
	copy(msg[48:64], sig[:])
	return nil
}

func (s *Signer) Verify(msg []byte) (bool, error) {
	if len(msg) < headerSize {
		return false, errShort
	}
	want := [16]byte(msg[48:64])
	if err := s.Sign(msg); err != nil {
		return false, err
	}
	return constantEqual(want[:], msg[48:64]), nil
}

func (s *Signer) cmac(msg []byte) [16]byte {
	n := (len(msg) + 15) / 16
	if n == 0 {
		n = 1
	}
	var x [16]byte
	var y [16]byte
	for i := range n - 1 {
		blk := msg[i*16 : (i+1)*16]
		for j := range 16 {
			y[j] = x[j] ^ blk[j]
		}
		s.aesBlock.Encrypt(x[:], y[:])
	}
	var last [16]byte
	remaining := msg[(n-1)*16:]
	if len(remaining) == 16 {
		for j := range 16 {
			last[j] = remaining[j] ^ s.cmacK1[j] ^ x[j]
		}
	} else {
		padded := cmacPad(remaining)
		for j := range 16 {
			last[j] = padded[j] ^ s.cmacK2[j] ^ x[j]
		}
	}
	var out [16]byte
	s.aesBlock.Encrypt(out[:], last[:])
	return out
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

func DeriveSigningKey(sessionKey []byte) []byte {
	return kdfCounter(sessionKey, []byte("SMB2AESCMAC\x00"), []byte("SmbSign\x00"))
}

func kdfCounter(ki, label, context []byte) []byte {
	mac := hmac.New(sha256.New, ki)
	mac.Write([]byte{0x00, 0x00, 0x00, 0x01})
	mac.Write(label)
	mac.Write([]byte{0x00})
	mac.Write(context)
	mac.Write([]byte{0x00, 0x00, 0x00, 0x80})
	return mac.Sum(nil)[:16]
}
