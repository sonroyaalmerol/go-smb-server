package ntlmssp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

func fieldLen(b []byte) int { return int(binary.LittleEndian.Uint16(b[0:2])) }
func fieldOff(b []byte) int { return int(binary.LittleEndian.Uint32(b[4:8])) }

func extractPayload(msg []byte, fields []byte) ([]byte, error) {
	l := fieldLen(fields)
	o := fieldOff(fields)
	if l == 0 {
		return nil, nil
	}
	if o+l > len(msg) {
		return nil, fmt.Errorf("ntlmssp: field offset/length out of range (%d:%d, msg=%d)", o, l, len(msg))
	}
	return msg[o : o+l], nil
}

const negotiateFixedLen = 32

type negotiateMessage struct {
	Flags       uint32
	DomainName  string
	Workstation string
}

func parseNegotiateMessage(b []byte) (*negotiateMessage, error) {
	if len(b) < negotiateFixedLen {
		return nil, fmt.Errorf("%w: negotiate needs %d bytes, got %d", ErrInvalidNTLMMessage, negotiateFixedLen, len(b))
	}
	if [8]byte(b[0:8]) != ntlmSignature {
		return nil, fmt.Errorf("%w: bad signature", ErrInvalidNTLMMessage)
	}
	if mt := binary.LittleEndian.Uint32(b[8:12]); mt != MsgNegotiate {
		return nil, fmt.Errorf("%w: not a NEGOTIATE message (type %d)", ErrInvalidNTLMMessage, mt)
	}
	m := &negotiateMessage{Flags: binary.LittleEndian.Uint32(b[12:16])}
	if d, err := extractPayload(b, b[16:24]); err == nil && d != nil {
		m.DomainName = string(d)
	}
	if w, err := extractPayload(b, b[24:32]); err == nil && w != nil {
		m.Workstation = string(w)
	}
	return m, nil
}

const challengeFixedLen = 56

type challengeMessage struct {
	Flags           uint32
	ServerChallenge [8]byte
	TargetName      string
	TargetInfo      []byte
}

func (c *challengeMessage) Marshal() ([]byte, error) {
	target := []byte(toUTF16LE(c.TargetName))
	payload := append([]byte(nil), target...)
	payload = append(payload, c.TargetInfo...)

	total := challengeFixedLen + len(payload)
	out := make([]byte, total)
	copy(out[0:8], ntlmSignature[:])
	binary.LittleEndian.PutUint32(out[8:12], MsgChallenge)
	binary.LittleEndian.PutUint16(out[12:14], uint16(len(target)))
	binary.LittleEndian.PutUint16(out[14:16], uint16(len(target)))
	binary.LittleEndian.PutUint32(out[16:20], uint32(challengeFixedLen))
	binary.LittleEndian.PutUint32(out[20:24], c.Flags)
	copy(out[24:32], c.ServerChallenge[:])
	binary.LittleEndian.PutUint16(out[40:42], uint16(len(c.TargetInfo)))
	binary.LittleEndian.PutUint16(out[42:44], uint16(len(c.TargetInfo)))
	binary.LittleEndian.PutUint32(out[44:48], uint32(challengeFixedLen+len(target)))
	copy(out[challengeFixedLen:], payload)
	return out, nil
}

const authenticateFixedLen = 88

type authenticateMessage struct {
	Flags               uint32
	DomainName          []byte
	UserName            []byte
	Workstation         []byte
	LmChallengeResponse []byte
	NtChallengeResponse []byte
	EncryptedSessionKey []byte
	MIC                 [16]byte
}

func parseAuthenticateMessage(b []byte) (*authenticateMessage, error) {
	if len(b) < authenticateFixedLen {
		return nil, fmt.Errorf("%w: authenticate needs %d bytes, got %d", ErrInvalidNTLMMessage, authenticateFixedLen, len(b))
	}
	if [8]byte(b[0:8]) != ntlmSignature {
		return nil, fmt.Errorf("%w: bad signature", ErrInvalidNTLMMessage)
	}
	if mt := binary.LittleEndian.Uint32(b[8:12]); mt != MsgAuthenticate {
		return nil, fmt.Errorf("%w: not an AUTHENTICATE message (type %d)", ErrInvalidNTLMMessage, mt)
	}
	m := &authenticateMessage{Flags: binary.LittleEndian.Uint32(b[60:64])}
	var err error
	if m.LmChallengeResponse, err = extractPayload(b, b[12:20]); err != nil {
		return nil, err
	}
	if m.NtChallengeResponse, err = extractPayload(b, b[20:28]); err != nil {
		return nil, err
	}
	if m.DomainName, err = extractPayload(b, b[28:36]); err != nil {
		return nil, err
	}
	if m.UserName, err = extractPayload(b, b[36:44]); err != nil {
		return nil, err
	}
	if m.Workstation, err = extractPayload(b, b[44:52]); err != nil {
		return nil, err
	}
	if m.EncryptedSessionKey, err = extractPayload(b, b[52:60]); err != nil {
		return nil, err
	}
	copy(m.MIC[:], b[64:80])
	return m, nil
}

func utf16String(b []byte) string {
	return decodeUTF16LE(b)
}

func decodeUTF16LE(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b) / 2)
	for i := 0; i+1 < len(b); i += 2 {
		sb.WriteRune(rune(uint16(b[i]) | uint16(b[i+1])<<8))
	}
	return sb.String()
}

var ErrShortMessage = errors.New("ntlmssp: short message")
