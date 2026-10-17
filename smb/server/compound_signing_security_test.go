package server

import (
	"encoding/binary"
	"testing"

	"github.com/sonroyaalmerol/go-smb-server/smb/signing"
	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

// TestCompoundSigningFinalOffsets verifies that each compound
// response signature covers its final NextCommand field.
func TestCompoundSigningFinalOffsets(t *testing.T) {
	const sessionID uint64 = 42

	signer, err := signing.NewSigner([]byte("0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}

	c := &conn{
		sessions: map[uint64]*session{
			sessionID: {signer: signer},
		},
	}

	first := wire.NewHeader(wire.CmdTreeConnect)
	first.SessionId = sessionID
	first.NextCommand = wire.HeaderSize
	first.Flags = wire.FlagServerToRedir

	second := wire.NewHeader(wire.CmdTreeConnect)
	second.SessionId = sessionID
	second.Flags = wire.FlagServerToRedir

	c.out = first.Append(nil)
	c.out = second.Append(c.out)

	if err := c.signResponseChain(); err != nil {
		t.Fatal(err)
	}

	if got := binary.LittleEndian.Uint32(c.out[20:24]); got != wire.HeaderSize {
		t.Fatalf("NextCommand = %d, want %d", got, wire.HeaderSize)
	}

	for i, part := range [][]byte{
		c.out[:wire.HeaderSize],
		c.out[wire.HeaderSize:],
	} {
		// Verify modifies its input, so use a copy.
		signed := append([]byte(nil), part...)
		ok, err := signer.Verify(signed)
		if err != nil || !ok {
			t.Fatalf("compound segment %d has invalid signature: %v", i, err)
		}
	}
}

// TestCompoundSigningRejectsMalformedOffset ensures malformed
// response framing cannot be accepted for transmission.
func TestCompoundSigningRejectsMalformedOffset(t *testing.T) {
	hdr := wire.NewHeader(wire.CmdTreeConnect)
	hdr.NextCommand = 65 // Not aligned to eight bytes.

	c := &conn{out: hdr.Append(nil)}

	if err := c.signResponseChain(); err == nil {
		t.Fatal("SECURITY FAILURE: malformed compound offset accepted")
	}
}
