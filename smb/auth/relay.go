package auth

import "context"

type RelayFunc func(ctx context.Context, spnegoToken []byte) (response []byte, sessionKey []byte, identity *Identity, err error)

type RelayFactory func() RelayFunc

type RelayAuthenticator struct {
	relay RelayFunc
}

func NewRelayAuthenticator(relayFactory RelayFactory) Factory {
	return func() Authenticator {
		return &RelayAuthenticator{relay: relayFactory()}
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
