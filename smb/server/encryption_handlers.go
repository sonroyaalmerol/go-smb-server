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
	if sess == nil || sess.decryptionKey == nil {
		return nil, errors.New("server: no decryption key for session")
	}
	if sess.decCCM == nil {
		ccm, err := encryption.NewAESCCM(sess.decryptionKey)
		if err != nil {
			return nil, err
		}
		sess.decCCM = ccm
	}
	return sess.decCCM.Open(transform)
}

func (c *conn) maybeSealResponse(out []byte) ([]byte, bool) {
	if len(out) < wire.HeaderSize {
		return nil, false
	}
	cmd := binary.LittleEndian.Uint16(out[12:14])
	if cmd == wire.CmdNegotiate || cmd == wire.CmdSessionSetup {
		return nil, false
	}
	sessID := binary.LittleEndian.Uint64(out[40:48])
	sess := c.getSession(sessID)
	if sess == nil || sess.encryptionKey == nil || !sess.requireEncrypt {
		return nil, false
	}
	if sess.encCCM == nil {
		ccm, err := encryption.NewAESCCM(sess.encryptionKey)
		if err != nil {
			c.log.Debug("seal: new ccm", "err", err)
			return nil, false
		}
		sess.encCCM = ccm
	}
	sealed, err := sess.encCCM.Seal(out, sessID)
	if err != nil {
		c.log.Debug("seal response", "err", err)
		return nil, false
	}
	return sealed, true
}

func (c *conn) negotiateCapabilities() uint32 {
	caps := wire.CapLargeMTU
	if c.srv.requireEnc {
		caps |= wire.CapEncryption
	}
	return caps
}
