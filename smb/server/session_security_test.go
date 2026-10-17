package server

import (
	"context"
	"testing"

	"github.com/sonroyaalmerol/go-smb-server/smb/auth"
	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

type sessionSecurityAuthenticator struct {
	result auth.AcceptResult
	err    error
}

func (a *sessionSecurityAuthenticator) Accept(_ context.Context, _ []byte) (auth.AcceptResult, error) {
	return a.result, a.err
}

func TestSessionSetupRejectsInvalidKeys(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"one_byte", []byte{1}},
		{"fifteen_bytes", make([]byte, 15)},
		{"seventeen_bytes", make([]byte, 17)},
		{"thirty_one_bytes", make([]byte, 31)},
		{"thirty_three_bytes", make([]byte, 33)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &conn{
				srv: &Server{
					authFactory: func() auth.Authenticator {
						return &sessionSecurityAuthenticator{
							result: auth.AcceptResult{
								Identity:   &auth.Identity{Username: "alice"},
								SessionKey: tt.key,
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

			if status != wire.StatusLogonFailure {
				t.Fatalf("status = %#x, want STATUS_LOGON_FAILURE", status)
			}
			if len(c.sessions) != 0 {
				t.Fatalf("failed authentication retained %d sessions", len(c.sessions))
			}
		})
	}
}

func TestSessionSetupAcceptsSupportedKeyLengths(t *testing.T) {
	for _, length := range []int{16, 32} {
		t.Run(string(rune('0'+length/16)), func(t *testing.T) {
			key := make([]byte, length)
			for i := range key {
				key[i] = byte(i + 1)
			}

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
				t.Fatalf("status = %#x, want success", status)
			}
			sess := c.getSession(hdr.SessionId)
			if sess == nil || !sess.authenticated || sess.signer == nil {
				t.Fatal("successful authentication lacks initialized session security")
			}
		})
	}
}

func TestSessionSetupCleansUpAuthenticationFailure(t *testing.T) {
	c := &conn{
		srv: &Server{
			authFactory: func() auth.Authenticator {
				return &sessionSecurityAuthenticator{err: auth.ErrLogonFailed}
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

	if status != wire.StatusLogonFailure {
		t.Fatalf("status = %#x, want STATUS_LOGON_FAILURE", status)
	}
	if len(c.sessions) != 0 {
		t.Fatalf("failed authentication retained %d sessions", len(c.sessions))
	}
}

func TestSessionSetupIncompleteHandshake(t *testing.T) {
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
		t.Fatalf("status = %#x, want MORE_PROCESSING_REQUIRED", status)
	}

	sess := c.getSession(hdr.SessionId)
	if sess == nil {
		t.Fatal("incomplete handshake session was removed")
	}
	if sess.authenticated || sess.signer != nil {
		t.Fatal("incomplete handshake incorrectly established security")
	}
}

func TestRejectedSessionCannotAccessShare(t *testing.T) {
	c := &conn{
		srv: &Server{
			authFactory: func() auth.Authenticator {
				return &sessionSecurityAuthenticator{
					result: auth.AcceptResult{
						Identity: &auth.Identity{Username: "alice"},
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

	if status != wire.StatusLogonFailure {
		t.Fatalf("setup status = %#x", status)
	}

	rejectedID := hdr.SessionId

	if c.getSession(rejectedID) != nil {
		t.Fatal("rejected session remains allocated")
	}

	treeHdr := wire.NewHeader(wire.CmdTreeConnect)
	treeHdr.SessionId = rejectedID

	status = c.dispatch(
		context.Background(),
		buildTreeConnect(rejectedID, `\\server\share`),
		&treeHdr,
		nil,
		false,
	)

	if status != wire.StatusUserSessionDeleted {
		t.Fatalf("tree connect status = %#x, want USER_SESSION_DELETED", status)
	}
}
