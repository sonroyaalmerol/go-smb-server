package auth

import "context"

type RelayFunc func(ctx context.Context, spnegoToken []byte) (response []byte, sessionKey []byte, identity *Identity, err error)

type RelayAuthenticator struct {
	relay RelayFunc
}

func NewRelayAuthenticator(relay RelayFunc) Factory {
	return func() Authenticator {
		return &RelayAuthenticator{relay: relay}
	}
}

func (a *RelayAuthenticator) Accept(ctx context.Context, token []byte) (AcceptResult, error) {
	resp, sessionKey, identity, err := a.relay(ctx, token)
	if err != nil {
		return AcceptResult{}, err
	}
	result := AcceptResult{OutputToken: resp}
	if identity != nil {
		result.Identity = identity
		result.SessionKey = sessionKey
	}
	return result, nil
}
