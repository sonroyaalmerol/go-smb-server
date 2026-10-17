package server

import (
	"context"
	"testing"

	"github.com/sonroyaalmerol/go-smb-server/smb/auth"
	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

// Authentication must activate the mandatory signing policy.
// Deriving a signing key alone does not require clients to sign requests.
func TestSessionSigningPolicyRequiredAfterAuthentication(t *testing.T) {
	key := []byte("0123456789abcdef")

	c := &conn{
		srv: &Server{
			authFactory: func() auth.Authenticator {
				return &sessionSecurityAuthenticator{
					result: auth.AcceptResult{
						Identity:   &auth.Identity{Username: "alice"},
						SessionKey: key,
					},
				}
			},
		},
		sessions: make(map[uint64]*session),
	}

	hdr := wire.NewHeader(wire.CmdSessionSetup)
	status := c.handleSessionSetup(
		context.Background(),
		buildSessionSetup([]byte{1}),
		&hdr,
	)
	if status != wire.StatusSuccess {
		t.Fatalf("authentication status = %#x", status)
	}

	sess := c.getSession(hdr.SessionId)
	if sess == nil || !sess.authenticated || sess.signer == nil {
		t.Fatal("authenticated session lacks signer")
	}
	if !sess.requireSign {
		t.Fatal("SECURITY FAILURE: authenticated session does not require signing")
	}

	unsigned := wire.NewHeader(wire.CmdEcho)
	unsigned.SessionId = hdr.SessionId

	if err := verifyCompoundRequestSignature(
		sess, &unsigned, unsigned.Append(nil),
	); err == nil {
		t.Fatal("SECURITY FAILURE: unsigned authenticated request accepted")
	}
}

// Incomplete handshakes must not be mistaken for authenticated sessions.
func TestSessionSigningPolicyIncompleteHandshake(t *testing.T) {
	c := &conn{
		srv: &Server{
			authFactory: func() auth.Authenticator {
				return &sessionSecurityAuthenticator{
					result: auth.AcceptResult{
						OutputToken: []byte{1, 2, 3},
					},
				}
			},
		},
		sessions: make(map[uint64]*session),
	}

	hdr := wire.NewHeader(wire.CmdSessionSetup)
	status := c.handleSessionSetup(
		context.Background(),
		buildSessionSetup([]byte{1}),
		&hdr,
	)
	if status != wire.StatusMoreProcessingRequired {
		t.Fatalf("handshake status = %#x", status)
	}

	sess := c.getSession(hdr.SessionId)
	if sess == nil {
		t.Fatal("incomplete session missing")
	}
	if sess.authenticated || sess.signer != nil || sess.requireSign {
		t.Fatal("SECURITY FAILURE: incomplete handshake activated signing")
	}
}
