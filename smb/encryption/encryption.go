package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

const TransformHeaderSize = 52

var transformProtocolId = [4]byte{0xFD, 'S', 'M', 'B'}

type AESCCM struct {
	block cipher.Block
}

func NewAESCCM(key []byte) (*AESCCM, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("encryption: AES-128-CCM requires a 16-byte key, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &AESCCM{block: block}, nil
}

func (c *AESCCM) Seal(msg []byte, sessionID uint64) ([]byte, error) {
	var nonce [16]byte
	ccmNonce := nonce[:11]
	if _, err := rand.Read(ccmNonce); err != nil {
		return nil, fmt.Errorf("encryption: nonce: %w", err)
	}

	out := make([]byte, TransformHeaderSize+len(msg))
	copy(out[0:4], transformProtocolId[:])
	copy(out[20:36], nonce[:])
	binary.LittleEndian.PutUint32(out[36:40], uint32(len(msg)))
	binary.LittleEndian.PutUint16(out[42:44], 0x0001)
	binary.LittleEndian.PutUint64(out[44:52], sessionID)

	ct := out[TransformHeaderSize:]
	copy(ct, msg)
	aad := out[20:TransformHeaderSize]
	tag := ccmEncryptInPlace(c.block, ccmNonce, aad, ct)
	copy(out[4:20], tag[:])
	return out, nil
}

func (c *AESCCM) Open(transform []byte) ([]byte, error) {
	if len(transform) < TransformHeaderSize {
		return nil, errors.New("encryption: transform shorter than header")
	}
	if [4]byte(transform[0:4]) != transformProtocolId {
		return nil, errors.New("encryption: bad transform protocol id")
	}
	origSize := binary.LittleEndian.Uint32(transform[36:40])
	if len(transform)-TransformHeaderSize != int(origSize) {
		return nil, fmt.Errorf("encryption: OriginalMessageSize %d != ciphertext %d", origSize, len(transform)-TransformHeaderSize)
	}
	nonce := transform[20:31]
	tag := transform[4:20]
	ct := transform[TransformHeaderSize:]
	aad := transform[20:TransformHeaderSize]

	if err := ccmDecryptInPlace(c.block, nonce, aad, ct, tag); err != nil {
		return nil, err
	}
	return ct, nil
}

func DeriveServerEncryptionKey(sessionKey []byte) []byte {
	return kdfCounter(sessionKey, []byte("SMB2AESCCM\x00"), []byte("ServerOut\x00"))
}

func DeriveServerDecryptionKey(sessionKey []byte) []byte {
	return kdfCounter(sessionKey, []byte("SMB2AESCCM\x00"), []byte("ServerIn \x00"))
}

func kdfCounter(ki, label, context []byte) []byte {
	var b []byte
	b = append(b, 0x00, 0x00, 0x00, 0x01)
	b = append(b, label...)
	b = append(b, 0x00)
	b = append(b, context...)
	b = append(b, 0x00, 0x00, 0x00, 0x80)
	mac := hmacSHA256(ki, b)
	return mac[:16]
}
