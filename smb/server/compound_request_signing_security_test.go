package server

import (
	"bytes"
	"testing"

	"github.com/sonroyaalmerol/go-smb-server/smb/signing"
	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

// TestCompoundRequestSigningSecurity checks that verification uses
// each original command, not the remaining compound buffer.
func TestCompoundRequestSigningSecurity(t *testing.T) {
	signer, err := signing.NewSigner([]byte("0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}

	sess := &session{
		authenticated: true,
		requireSign:   true,
		signer:        signer,
	}

	first := wire.NewHeader(wire.CmdEcho)
	first.SessionId = 42
	first.Flags = wire.FlagSigned
	first.NextCommand = wire.HeaderSize

	second := wire.NewHeader(wire.CmdEcho)
	second.SessionId = 42
	second.Flags = wire.FlagSigned

	a := first.Append(nil)
	b := second.Append(nil)

	if err := signer.Sign(a); err != nil {
		t.Fatal(err)
	}
	if err := signer.Sign(b); err != nil {
		t.Fatal(err)
	}

	compound := append(append([]byte(nil), a...), b...)
	original := append([]byte(nil), compound...)

	for i, tc := range []struct {
		hdr wire.Header
		msg []byte
	}{
		{first, compound[:wire.HeaderSize]},
		{second, compound[wire.HeaderSize:]},
	} {
		if err := verifyCompoundRequestSignature(
			sess, &tc.hdr, tc.msg,
		); err != nil {
			t.Fatalf("segment %d: %v", i, err)
		}
	}

	if !bytes.Equal(compound, original) {
		t.Fatal("SECURITY FAILURE: verification modified request bytes")
	}

	// The first command's signature must not cover the second command.
	if err := verifyCompoundRequestSignature(
		sess, &first, compound,
	); err == nil {
		t.Fatal("SECURITY FAILURE: unbounded compound verification accepted")
	}

	tampered := append([]byte(nil), a...)
	tampered[24] ^= 1
	if err := verifyCompoundRequestSignature(
		sess, &first, tampered,
	); err == nil {
		t.Fatal("SECURITY FAILURE: tampered request accepted")
	}

	missing := &session{authenticated: true, requireSign: true}
	if err := verifyCompoundRequestSignature(
		missing, &first, a,
	); err == nil {
		t.Fatal("SECURITY FAILURE: missing signer accepted")
	}

	unsigned := wire.NewHeader(wire.CmdEcho)
	unsigned.SessionId = 42
	if err := verifyCompoundRequestSignature(
		sess, &unsigned, unsigned.Append(nil),
	); err == nil {
		t.Fatal("SECURITY FAILURE: unsigned required request accepted")
	}
}
