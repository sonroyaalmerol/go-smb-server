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

	header := make([]byte, TransformHeaderSize)
	copy(header[0:4], transformProtocolId[:])
	copy(header[20:36], nonce[:])
	binary.LittleEndian.PutUint32(header[36:40], uint32(len(msg)))
	binary.LittleEndian.PutUint16(header[42:44], 0x0001)
	binary.LittleEndian.PutUint64(header[44:52], sessionID)

	ct, tag := ccmEncrypt(c.block, ccmNonce, header[20:TransformHeaderSize], msg)
	copy(header[4:20], tag)

	out := header
	out = append(out, ct...)
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
	tag := [16]byte(transform[4:20])
	ct := transform[TransformHeaderSize:]

	aad := transform[20:TransformHeaderSize]

	pt, err := ccmDecrypt(c.block, nonce, aad, ct, tag[:])
	if err != nil {
		return nil, err
	}
	return pt, nil
}

func DeriveServerEncryptionKey(sessionKey []byte) []byte {
	return kdfCounter(sessionKey, []byte("SMB2AESCCM\x00"), []byte("ServerOut\x00"))
}

func DeriveServerDecryptionKey(sessionKey []byte) []byte {
	return kdfCounter(sessionKey, []byte("SMB2AESCCM\x00"), []byte("ServerIn \x00"))
}

func kdfCounter(ki, label, context []byte) []byte {
	mac := hmacSHA256(ki, func() []byte {
		var b []byte
		b = append(b, 0x00, 0x00, 0x00, 0x01)
		b = append(b, label...)
		b = append(b, 0x00)
		b = append(b, context...)
		b = append(b, 0x00, 0x00, 0x00, 0x80)
		return b
	}())
	_ = mac
	return mac[:16]
}
