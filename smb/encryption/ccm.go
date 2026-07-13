package encryption

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

func ccmEncrypt(block cipher.Block, nonce, aad, plaintext []byte) ([]byte, []byte) {
	tag := cbcMac(block, nonce, aad, plaintext)
	s0 := ctrBlock(block, nonce, 0)
	dataStream := ctrStream(block, nonce, len(plaintext))
	ct := xorCopy(plaintext, dataStream)
	tagMasked := xorCopy(tag[:], s0)
	return ct, tagMasked
}

func ccmDecrypt(block cipher.Block, nonce, aad, ct []byte, tag []byte) ([]byte, error) {
	s0 := ctrBlock(block, nonce, 0)
	dataStream := ctrStream(block, nonce, len(ct))
	pt := xorCopy(ct, dataStream)
	expectedTag := xorCopy(tag, s0)
	computed := cbcMac(block, nonce, aad, pt)
	if !constTimeEqual(expectedTag, computed[:]) {
		return nil, errors.New("encryption: CCM authentication failed")
	}
	return pt, nil
}

func ctrBlock(block cipher.Block, nonce []byte, counter uint64) []byte {
	l := 15 - len(nonce)
	var ai [16]byte
	ai[0] = byte(l - 1)
	copy(ai[1:], nonce)
	putBE(ai[16-l:16], counter)
	var s [16]byte
	block.Encrypt(s[:], ai[:])
	return s[:]
}

func cbcMac(block cipher.Block, nonce, aad, data []byte) [16]byte {
	l := 15 - len(nonce)
	flags := byte(0)
	if len(aad) > 0 {
		flags |= 0x40
	}
	flags |= byte(l - 1)

	var b0 [16]byte
	b0[0] = flags
	copy(b0[1:], nonce)
	putBE(b0[16-l:16], uint64(len(data)))

	var x [16]byte
	xorBlock(x[:], b0[:])
	block.Encrypt(x[:], x[:])

	if len(aad) > 0 {
		x = macBlocks(block, x, encodeAADLength(aad))
		x = macBlocks(block, x, aad)
	}
	x = macBlocks(block, x, data)
	return x
}

func macBlocks(block cipher.Block, state [16]byte, buf []byte) [16]byte {
	for i := 0; i < len(buf); i += 16 {
		var blk [16]byte
		if i+16 <= len(buf) {
			copy(blk[:], buf[i:i+16])
		} else {
			copy(blk[:], buf[i:])
		}
		xorBlock(state[:], blk[:])
		block.Encrypt(state[:], state[:])
	}
	return state
}

func encodeAADLength(aad []byte) []byte {
	n := len(aad)
	if n < 0xFF00 {
		return []byte{byte(n >> 8), byte(n)}
	}
	return []byte{0xFF, 0xFE, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

func ctrStream(block cipher.Block, nonce []byte, length int) []byte {
	l := 15 - len(nonce)
	out := make([]byte, 0, length)
	counter := uint64(1)
	for len(out) < length {
		var ai [16]byte
		ai[0] = byte(l - 1)
		copy(ai[1:], nonce)
		putBE(ai[16-l:16], counter)
		var s [16]byte
		block.Encrypt(s[:], ai[:])
		take := min(16, length-len(out))
		out = append(out, s[:take]...)
		counter++
	}
	return out
}

func xorCopy(a, b []byte) []byte {
	n := min(len(a), len(b))
	out := make([]byte, n)
	for i := range n {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func xorBlock(dst, src []byte) {
	for i := range 16 {
		dst[i] ^= src[i]
	}
}

func putBE(dst []byte, v uint64) {
	for i := len(dst) - 1; i >= 0; i-- {
		dst[i] = byte(v)
		v >>= 8
	}
}

func constTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
