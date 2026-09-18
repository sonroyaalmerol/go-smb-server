package ntlmssp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sonroyaalmerol/go-smb-server/smb/auth"
)

type CredentialLookup interface {
	LookupNTOWFv2(ctx context.Context, domain, user string) (key []byte, err error)
}

var ErrUnknownUser = errors.New("ntlmssp: unknown user")

type serverAuthenticator struct {
	lookup CredentialLookup

	stage      int
	challenge  [8]byte
	targetName string
	negotiate  []byte

	domain string
	user   string

	// spnego records whether the client wrapped its token in SPNEGO, so
	// replies use the same framing.
	spnego bool
}

func NewServer(lookup CredentialLookup, serverName string) auth.Factory {
	return func() auth.Authenticator {
		return &serverAuthenticator{lookup: lookup, targetName: serverName}
	}
}

func (s *serverAuthenticator) Accept(ctx context.Context, token []byte) (auth.AcceptResult, error) {
	msg, spnego, err := unwrapSPNEGOToken(token)
	if err != nil {
		return auth.AcceptResult{}, fmt.Errorf("ntlmssp: unwrap spnego: %w", err)
	}
	s.spnego = spnego

	switch s.stage {
	case 0:
		return s.handleNegotiate(msg)
	case 1:
		return s.handleAuthenticate(ctx, msg)
	default:
		return auth.AcceptResult{}, errors.New("ntlmssp: handshake already complete")
	}
}

func (s *serverAuthenticator) handleNegotiate(msg []byte) (auth.AcceptResult, error) {
	if _, err := parseNegotiateMessage(msg); err != nil {
		return auth.AcceptResult{}, fmt.Errorf("ntlmssp: parse negotiate: %w", err)
	}
	if _, err := rand.Read(s.challenge[:]); err != nil {
		return auth.AcceptResult{}, fmt.Errorf("ntlmssp: generate challenge: %w", err)
	}
	s.negotiate = append([]byte(nil), msg...)
	s.stage = 1

	resp := &challengeMessage{
		Flags:           serverChallengeFlags,
		ServerChallenge: s.challenge,
		TargetName:      s.targetName,
		TargetInfo:      buildTargetInfo(s.targetName),
	}
	body, err := resp.Marshal()
	if err != nil {
		return auth.AcceptResult{}, err
	}
	if !s.spnego {
		return auth.AcceptResult{OutputToken: body}, nil
	}
	out, err := wrapSPNEGOChallenge(body)
	if err != nil {
		return auth.AcceptResult{}, err
	}
	return auth.AcceptResult{OutputToken: out}, nil
}

func (s *serverAuthenticator) handleAuthenticate(ctx context.Context, msg []byte) (auth.AcceptResult, error) {
	am, err := parseAuthenticateMessage(msg)
	if err != nil {
		return auth.AcceptResult{}, fmt.Errorf("ntlmssp: parse authenticate: %w", err)
	}
	s.domain = utf16String(am.DomainName)
	s.user = utf16String(am.UserName)

	if len(am.NtChallengeResponse) < 16 {
		return auth.AcceptResult{}, auth.ErrLogonFailed
	}

	key, err := s.lookup.LookupNTOWFv2(ctx, s.domain, s.user)
	if err != nil {
		return auth.AcceptResult{}, auth.ErrLogonFailed
	}

	proof := computeNTProofStr(key, s.challenge[:], am.NtChallengeResponse)
	if !ctEqual(proof, am.NtChallengeResponse[:16]) {
		return auth.AcceptResult{}, auth.ErrLogonFailed
	}

	sessionKey := sessionBaseKey(key, proof)
	if am.Flags&FlagNegotiateKeyExch != 0 && len(am.EncryptedSessionKey) == 16 {
		sessionKey = rc4Decrypt(sessionKey, am.EncryptedSessionKey)
	}

	s.stage = 2
	ident := &auth.Identity{
		Username: s.user,
		Domain:   s.domain,
	}
	if !s.spnego {
		// Raw NTLMSSP ends with an empty security buffer.
		return auth.AcceptResult{Identity: ident, SessionKey: sessionKey}, nil
	}
	acceptToken, err := wrapSPNEGOAccept()
	if err != nil {
		return auth.AcceptResult{}, fmt.Errorf("ntlmssp: wrap accept: %w", err)
	}
	return auth.AcceptResult{Identity: ident, SessionKey: sessionKey, OutputToken: acceptToken}, nil
}

// AV_PAIR attribute IDs (MS-NLMP section 2.2.2.1).
const (
	avEOL        uint16 = 0x00
	avNbCompName uint16 = 0x01
	avNbDomName  uint16 = 0x02
	avDnsComp    uint16 = 0x03
	avDnsDom     uint16 = 0x04
	avTimestamp  uint16 = 0x07
)

// buildTargetInfo constructs the CHALLENGE_MESSAGE TargetInfo payload: a list
// of AV_PAIRs the client folds into its NTLMv2 response, terminated by
// MsvAvEOL. It carries the same pairs Samba sends, including the timestamp
// Windows expects; a sparser list is rejected by Windows clients.
func buildTargetInfo(serverName string) []byte {
	if serverName == "" {
		// Minimal valid TargetInfo: just the terminator.
		return []byte{0x00, 0x00, 0x00, 0x00}
	}
	name := []byte(toUTF16LE(serverName))
	dnsName := []byte(toUTF16LE(strings.ToLower(serverName)))
	var out []byte
	out = appendAV(out, avNbDomName, name)
	out = appendAV(out, avNbCompName, name)
	out = appendAV(out, avDnsDom, nil)
	out = appendAV(out, avDnsComp, dnsName)
	out = appendAV(out, avTimestamp, nowFiletime())
	out = appendAV(out, avEOL, nil)
	return out
}

// nowFiletime returns the current time as a Windows FILETIME: 100-nanosecond
// intervals since 1601-01-01.
func nowFiletime() []byte {
	const unixEpochFiletime = 116_444_736_000_000_000
	out := make([]byte, 8)
	binary.LittleEndian.PutUint64(out, uint64(time.Now().UnixNano()/100)+unixEpochFiletime)
	return out
}

// appendAV encodes one AV_PAIR: AvId(2) + AvLen(2) + Value.
func appendAV(out []byte, id uint16, value []byte) []byte {
	out = append(out, byte(id), byte(id>>8))
	out = append(out, byte(len(value)), byte(len(value)>>8))
	return append(out, value...)
}
