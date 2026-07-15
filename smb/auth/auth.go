package auth

import (
	"context"
	"errors"
)

type Identity struct {
	Username string
	Domain   string
	SID      string
	Groups   []string
}

type AcceptResult struct {
	OutputToken []byte
	Identity    *Identity
	SessionKey  []byte
}

type Authenticator interface {
	Accept(ctx context.Context, input []byte) (AcceptResult, error)
}

type Factory func() Authenticator

var ErrLogonFailed = errors.New("auth: logon failed")

func AlwaysAllowFactory() Factory {
	return func() Authenticator { return alwaysAllowAuthenticator{} }
}

type alwaysAllowAuthenticator struct{}

func (alwaysAllowAuthenticator) Accept(_ context.Context, _ []byte) (AcceptResult, error) {
	return AcceptResult{Identity: &Identity{Username: "guest"}}, nil
}
