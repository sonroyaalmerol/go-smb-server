package server

import (
	"encoding/binary"
	"testing"

	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

// TestCompoundEncryptionRejectsMixedSessions ensures one compound
// response cannot combine different session security policies.
// A transform header identifies one encryption session, so accepting
// mixed-session chains risks sending protected data as plaintext.
func TestCompoundEncryptionRejectsMixedSessions(t *testing.T) {
	const protectedID uint64 = 42

	c := &conn{
		sessions: map[uint64]*session{
			protectedID: {
				authenticated:  true,
				requireEncrypt: true,
				encryptionKey:  []byte("0123456789abcdef"),
			},
		},
	}

	makeCompound := func(firstCmd uint16, firstID uint64) []byte {
		first := wire.NewHeader(firstCmd)
		first.SessionId = firstID
		first.NextCommand = wire.HeaderSize
		first.Flags = wire.FlagServerToRedir

		second := wire.NewHeader(wire.CmdTreeConnect)
		second.SessionId = protectedID
		second.Flags = wire.FlagServerToRedir

		return second.Append(first.Append(nil))
	}

	tests := []struct {
		name string
		msg  []byte
	}{
		{
			name: "plaintext_session_followed_by_encrypted_session",
			msg:  makeCompound(wire.CmdEcho, 0),
		},
		{
			name: "session_setup_followed_by_encrypted_session",
			msg:  makeCompound(wire.CmdSessionSetup, 0),
		},
		{
			name: "different_sessions_in_one_compound",
			msg:  makeCompound(wire.CmdEcho, 99),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := append([]byte(nil), tt.msg...)

			sealed, err := c.maybeSealResponse(tt.msg)
			if err == nil {
				t.Fatalf(
					"SECURITY FAILURE: mixed-session compound accepted; output length=%d",
					len(sealed),
				)
			}
			if len(sealed) != 0 {
				t.Fatal("SECURITY FAILURE: rejected response returned sendable bytes")
			}

			// The rejection path should not corrupt the caller's buffer.
			if len(original) != len(tt.msg) {
				t.Fatal("response length unexpectedly changed")
			}
			for i := range original {
				if original[i] != tt.msg[i] {
					t.Fatal("rejection modified response bytes")
				}
			}
		})
	}
}

// TestCompoundEncryptionRejectsMalformedOffsets ensures a malformed
// response chain cannot bypass security policy evaluation.
func TestCompoundEncryptionRejectsMalformedOffsets(t *testing.T) {
	c := &conn{sessions: make(map[uint64]*session)}

	h := wire.NewHeader(wire.CmdEcho)
	h.Flags = wire.FlagServerToRedir

	for _, offset := range []uint32{1, 63, 65, 72} {
		t.Run("offset_"+stringOffset(offset), func(t *testing.T) {
			h.NextCommand = offset
			msg := h.Append(nil)
			binary.LittleEndian.PutUint32(msg[20:24], offset)

			sealed, err := c.maybeSealResponse(msg)
			if err == nil || len(sealed) != 0 {
				t.Fatal("SECURITY FAILURE: malformed response chain accepted")
			}
		})
	}
}

func stringOffset(n uint32) string {
	if n == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
