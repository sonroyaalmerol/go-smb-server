package ntlmssp

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/sonroyaalmerol/go-smb-server/smb/auth"
)

type CredentialLookup interface {
	LookupNTOWFv2(ctx context.Context, domain, user string) (key []byte, err error)
}

var ErrUnknownUser = errors.New("ntlmssp: unknown user")

type ServerAuthenticator struct {
	lookup CredentialLookup

	stage      int
	challenge  [8]byte
	targetName string
	negotiate  []byte

	domain string
	user   string
}

func NewServer(lookup CredentialLookup, serverName string) auth.Factory {
	return func() auth.Authenticator {
		return &ServerAuthenticator{lookup: lookup, targetName: serverName}
	}
}

func (s *ServerAuthenticator) Accept(ctx context.Context, token []byte) (auth.AcceptResult, error) {
	msg, err := UnwrapSPNEGOToken(token)
	if err != nil {
		return auth.AcceptResult{}, fmt.Errorf("ntlmssp: unwrap spnego: %w", err)
	}

	switch s.stage {
	case 0:
		return s.handleNegotiate(msg)
	case 1:
		return s.handleAuthenticate(ctx, msg)
	default:
		return auth.AcceptResult{}, errors.New("ntlmssp: handshake already complete")
	}
}

func (s *ServerAuthenticator) handleNegotiate(msg []byte) (auth.AcceptResult, error) {
	neg, err := ParseNegotiateMessage(msg)
	if err != nil {
		return auth.AcceptResult{}, fmt.Errorf("ntlmssp: parse negotiate: %w", err)
	}
	_ = neg
	if _, err := rand.Read(s.challenge[:]); err != nil {
		return auth.AcceptResult{}, fmt.Errorf("ntlmssp: generate challenge: %w", err)
	}
	s.negotiate = append([]byte(nil), msg...)
	s.stage = 1

	resp := &ChallengeMessage{
		Flags:           serverChallengeFlags,
		ServerChallenge: s.challenge,
		TargetName:      s.targetName,
	}
	body, err := resp.Marshal()
	if err != nil {
		return auth.AcceptResult{}, err
	}
	out, err := WrapSPNEGOChallenge(body)
	if err != nil {
		return auth.AcceptResult{}, err
	}
	return auth.AcceptResult{OutputToken: out}, nil
}

func (s *ServerAuthenticator) handleAuthenticate(ctx context.Context, msg []byte) (auth.AcceptResult, error) {
	am, err := ParseAuthenticateMessage(msg)
	if err != nil {
		return auth.AcceptResult{}, fmt.Errorf("ntlmssp: parse authenticate: %w", err)
	}
	s.domain = UTF16String(am.DomainName)
	s.user = UTF16String(am.UserName)

	if len(am.NtChallengeResponse) < 16 {
		return auth.AcceptResult{}, auth.ErrLogonFailed
	}

	key, err := s.lookup.LookupNTOWFv2(ctx, s.domain, s.user)
	if err != nil {
		return auth.AcceptResult{}, auth.ErrLogonFailed
	}

	proof := ComputeNTProofStr(key, s.challenge[:], am.NtChallengeResponse)
	if !ctEqual(proof, am.NtChallengeResponse[:16]) {
		return auth.AcceptResult{}, auth.ErrLogonFailed
	}

	sessionKey := SessionBaseKey(key, proof)
	if am.Flags&FlagNegotiateKeyExch != 0 && len(am.EncryptedSessionKey) == 16 {
		sessionKey = rc4Decrypt(sessionKey, am.EncryptedSessionKey)
	}

	s.stage = 2
	ident := &auth.Identity{
		Username: s.user,
		Domain:   s.domain,
	}
	return auth.AcceptResult{Identity: ident, SessionKey: sessionKey}, nil
}
