package server

import (
	"encoding/binary"
	"errors"
	"fmt"

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

// maybeSealResponse returns only wire-safe response bytes.
// Encryption failures must never downgrade a response to plaintext.
// It validates every compound response segment before
// permitting plaintext or selecting a transform encryption session.
// MS-SMB2 compound messages use NextCommand to delimit each SMB2
// header and command. A transform identifies only one session, so
// mixed-session compounds are rejected rather than risk disclosure.
func (c *conn) maybeSealResponse(out []byte) ([]byte, error) {
	if len(out) < wire.HeaderSize {
		return nil, errors.New("server: response shorter than SMB header")
	}

	var sessionID uint64
	var command uint16
	first := true
	count := 0

	for off := 0; off < len(out); {
		remaining := len(out) - off
		if remaining < wire.HeaderSize {
			return nil, errors.New("server: truncated compound response")
		}

		var hdr wire.Header
		if err := hdr.Parse(out[off:]); err != nil {
			return nil, fmt.Errorf("server: invalid response header: %w", err)
		}
		if hdr.StructureSize != wire.HeaderSize {
			return nil, errors.New("server: invalid response header size")
		}

		if first {
			sessionID = hdr.SessionId
			command = hdr.Command
			first = false
		} else {
			if hdr.SessionId != sessionID {
				return nil, errors.New("server: mixed-session compound response")
			}
			if hdr.Command == wire.CmdNegotiate ||
				hdr.Command == wire.CmdSessionSetup {
				return nil, errors.New(
					"server: negotiation/setup inside compound response")
			}
		}

		count++

		if hdr.NextCommand == 0 {
			break
		}

		// Every nonterminal offset must point to a complete next
		// header and be aligned to eight bytes. Validate before
		// inspecting or transmitting any part of the chain.
		if hdr.NextCommand < wire.HeaderSize ||
			hdr.NextCommand%8 != 0 ||
			uint64(hdr.NextCommand) >
				uint64(remaining-wire.HeaderSize) {
			return nil, errors.New("server: invalid compound response offset")
		}

		off += int(hdr.NextCommand)
	}

	// These protocol-establishment responses are only permitted
	// standalone, never as an exemption for later compound commands.
	if command == wire.CmdNegotiate || command == wire.CmdSessionSetup {
		if count != 1 {
			return nil, errors.New(
				"server: compound negotiation/setup response")
		}
		return out, nil
	}

	sess := c.getSession(sessionID)
	if sess == nil {
		// Preserve the existing single-response behavior for error
		// replies referencing an unavailable session. Multi-command
		// responses must have an established session security context.
		if count != 1 {
			return nil, errors.New(
				"server: compound response without session")
		}
		return out, nil
	}

	if !sess.requireEncrypt {
		return out, nil
	}

	if len(sess.encryptionKey) == 0 {
		return nil, errors.New(
			"server: encrypted session missing encryption key")
	}

	if sess.encCCM == nil {
		ccm, err := encryption.NewAESCCM(sess.encryptionKey)
		if err != nil {
			return nil, fmt.Errorf(
				"server: initialize response encryption: %w", err)
		}
		sess.encCCM = ccm
	}

	sealed, err := sess.encCCM.Seal(out, sessionID)
	if err != nil {
		return nil, fmt.Errorf("server: seal response: %w", err)
	}
	return sealed, nil
}

func (c *conn) negotiateCapabilities() uint32 {
	caps := wire.CapLargeMTU
	if c.srv.requireEnc {
		caps |= wire.CapEncryption
	}
	return caps
}
