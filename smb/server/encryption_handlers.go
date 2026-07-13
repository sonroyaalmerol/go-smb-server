package server

import (
	"encoding/binary"
	"errors"

	"github.com/sonroyaalmerol/go-smb-server/smb/encryption"
	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

func (c *conn) openTransform(transform []byte) ([]byte, error) {
	if len(transform) < encryption.TransformHeaderSize {
		return nil, errors.New("server: transform shorter than header")
	}
	sessID := binary.LittleEndian.Uint64(transform[44:52])
	sess := c.getSession(sessID)
	if sess == nil || sess.encryptionKey == nil {
		return nil, errors.New("server: no encryption key for session")
	}
	ccm, err := encryption.NewAESCCM(encryption.DeriveServerDecryptionKey(sess.encryptionKey))
	if err != nil {
		return nil, err
	}
	return ccm.Open(transform)
}

func (c *conn) maybeSealResponse(out []byte) ([]byte, bool) {
	if len(out) < wire.HeaderSize {
		return nil, false
	}
	sessID := binary.LittleEndian.Uint64(out[40:48])
	sess := c.getSession(sessID)
	if sess == nil || sess.encryptionKey == nil || !sess.requireEncrypt {
		return nil, false
	}
	ccm, err := encryption.NewAESCCM(sess.encryptionKey)
	if err != nil {
		c.log.Debug("seal: new ccm", "err", err)
		return nil, false
	}
	sealed, err := ccm.Seal(out, sessID)
	if err != nil {
		c.log.Debug("seal response", "err", err)
		return nil, false
	}
	return sealed, true
}

// negotiateCapabilities returns the server capabilities to advertise in the
// NEGOTIATE response: always LargeMTU; Encryption when the server requires it.
func (c *conn) negotiateCapabilities() uint32 {
	caps := wire.CapLargeMTU
	if c.srv.requireEnc {
		caps |= wire.CapEncryption
	}
	return caps
}
