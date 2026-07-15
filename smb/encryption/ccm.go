package encryption

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

func ccmEncryptInPlace(block cipher.Block, nonce, aad, data []byte) [16]byte {
	tag := cbcMac(block, nonce, aad, data)
	var s0 [16]byte
	ctrEncryptBlock(block, nonce, 0, &s0)
	ctrXorInPlace(block, nonce, data)
	xorBlock16(tag[:], s0[:])
	return tag
}

func ccmDecryptInPlace(block cipher.Block, nonce, aad, data []byte, tag []byte) error {
	var s0 [16]byte
	ctrEncryptBlock(block, nonce, 0, &s0)
	ctrXorInPlace(block, nonce, data)
	var expectedTag [16]byte
	for i := range 16 {
		expectedTag[i] = tag[i] ^ s0[i]
	}
	computed := cbcMac(block, nonce, aad, data)
	if !constTimeEqual(expectedTag[:], computed[:]) {
		return errors.New("encryption: CCM authentication failed")
	}
	return nil
}

func ctrEncryptBlock(block cipher.Block, nonce []byte, counter uint64, out *[16]byte) {
	l := 15 - len(nonce)
	out[0] = byte(l - 1)
	copy(out[1:], nonce)
	putBE(out[16-l:16], counter)
	var tmp [16]byte
	block.Encrypt(tmp[:], out[:])
	copy(out[:], tmp[:])
}

func ctrXorInPlace(block cipher.Block, nonce []byte, data []byte) {
	l := 15 - len(nonce)
	var counter uint64 = 1
	var ai [16]byte
	var s [16]byte
	ai[0] = byte(l - 1)
	copy(ai[1:], nonce)
	for i := 0; i < len(data); i += 16 {
		putBE(ai[16-l:16], counter)
		block.Encrypt(s[:], ai[:])
		end := min(i+16, len(data))
		for j := i; j < end; j++ {
			data[j] ^= s[j-i]
		}
		counter++
	}
}

func cbcMac(block cipher.Block, nonce, aad, data []byte) [16]byte {
	l := 15 - len(nonce)
	const tagSize = 16
	flags := byte(0)
	if len(aad) > 0 {
		flags |= 0x40
	}
	flags |= byte(((tagSize-2)/2)&0x7) << 3
	flags |= byte(l - 1)

	var b0 [16]byte
	b0[0] = flags
	copy(b0[1:], nonce)
	putBE(b0[16-l:16], uint64(len(data)))

	var x [16]byte
	xorBlock16(x[:], b0[:])
	block.Encrypt(x[:], x[:])

	if len(aad) > 0 {
		var aadBuf [256]byte
		aadEncoded := encodeAADLengthInto(aadBuf[:], aad)
		x = macBlocks(block, x, aadEncoded)
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
		xorBlock16(state[:], blk[:])
		block.Encrypt(state[:], state[:])
	}
	return state
}

func encodeAADLengthInto(buf, aad []byte) []byte {
	n := len(aad)
	var off int
	if n < 0xFF00 {
		buf[0] = byte(n >> 8)
		buf[1] = byte(n)
		off = 2
	} else {
		buf[0] = 0xFF
		buf[1] = 0xFE
		buf[2] = byte(n >> 24)
		buf[3] = byte(n >> 16)
		buf[4] = byte(n >> 8)
		buf[5] = byte(n)
		off = 6
	}
	copy(buf[off:], aad)
	return buf[:off+len(aad)]
}

func xorBlock16(dst, src []byte) {
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
