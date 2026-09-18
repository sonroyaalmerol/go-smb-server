package ntlmssp

import (
	"crypto/rc4"
	"crypto/subtle"
	"encoding/asn1"
	"errors"
	"fmt"
	"sync"
)

var ntlmOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}

// unwrapSPNEGOToken returns the NTLMSSP message inside token, and whether it
// arrived wrapped in SPNEGO. Callers must answer in the framing they were
// given: the Linux kernel SMB client sends raw NTLMSSP and rejects an
// SPNEGO-wrapped challenge ("blob signature incorrect").
func unwrapSPNEGOToken(token []byte) ([]byte, bool, error) {
	if isNTLMSSP(token) {
		return token, false, nil
	}
	if len(token) > 0 && token[0] == 0x60 {
		clone := append([]byte{0x30}, token[1:]...)
		var ict struct {
			OID  asn1.ObjectIdentifier
			Init asn1.RawValue `asn1:"explicit,optional,tag:0"`
			Resp asn1.RawValue `asn1:"explicit,optional,tag:1"`
		}
		if _, err := asn1.Unmarshal(clone, &ict); err == nil {
			if m := scanForMechToken(ict.Init.Bytes); m != nil {
				return m, true, nil
			}
			if m := scanForRespToken(ict.Resp.Bytes); m != nil {
				return m, true, nil
			}
		}
	}
	if ntlm, ok := findContextTag2(token); ok && isNTLMSSP(ntlm) {
		return ntlm, true, nil
	}
	if len(token) > 0 && token[0] == 0xA1 {
		var outer struct {
			Inner struct {
				NegState      asn1.Enumerated       `asn1:"optional,explicit,tag:0"`
				SupportedMech asn1.ObjectIdentifier `asn1:"optional,explicit,tag:1"`
				ResponseToken []byte                `asn1:"optional,explicit,tag:2"`
			}
		}
		clone := append([]byte{0x30}, token[1:]...)
		if _, err := asn1.Unmarshal(clone, &outer); err == nil && len(outer.Inner.ResponseToken) > 0 && isNTLMSSP(outer.Inner.ResponseToken) {
			return outer.Inner.ResponseToken, true, nil
		}
	}
	return nil, false, fmt.Errorf("spnego: could not locate NTLMSSP token")
}

func scanForMechToken(negTokenInit []byte) []byte {
	return scanTag2OctetString(negTokenInit)
}

func scanForRespToken(negTokenResp []byte) []byte {
	return scanTag2OctetString(negTokenResp)
}

func scanTag2OctetString(raw []byte) []byte {
	for i := 0; i+2 < len(raw); i++ {
		if raw[i] != 0xA2 {
			continue
		}
		inner, err := parseContextTag(raw[i:])
		if err != nil || len(inner) < 2 {
			continue
		}
		if inner[0] == 0x04 {
			token, err := parseContextTag(inner)
			if err == nil && isNTLMSSP(token) {
				return token
			}
		}
		if isNTLMSSP(inner) {
			return inner
		}
	}
	return nil
}

func findContextTag2(raw []byte) ([]byte, bool) {
	for i := 0; i+1 < len(raw); i++ {
		if raw[i] != 0xA2 {
			continue
		}
		if inner, err := parseContextTag(raw[i:]); err == nil {
			return inner, true
		}
	}
	return nil, false
}

func isNTLMSSP(b []byte) bool { return len(b) >= 8 && [8]byte(b[0:8]) == ntlmSignature }

func parseContextTag(b []byte) ([]byte, error) {
	if len(b) < 2 {
		return nil, errors.New("spnego: short tag")
	}
	idx := 1
	length := int(b[idx])
	idx++
	if length&0x80 != 0 {
		n := length & 0x7F
		if idx+n > len(b) {
			return nil, errors.New("spnego: truncated length")
		}
		length = 0
		for j := range n {
			length = length<<8 | int(b[idx+j])
		}
		idx += n
	}
	if idx+length > len(b) {
		return nil, errors.New("spnego: value truncated")
	}
	return b[idx : idx+length], nil
}

var spnegoOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 2}

// NegTokenInitNTLM returns the SPNEGO token a server puts in its NEGOTIATE
// response to advertise NTLM. Windows needs this advertisement: with an
// empty blob its SSPI picks a mechanism on its own and then fails the
// session setup with STATUS_INVALID_PARAMETER.
var NegTokenInitNTLM = sync.OnceValue(func() []byte {
	init := struct {
		MechTypes []asn1.ObjectIdentifier `asn1:"explicit,tag:0"`
	}{[]asn1.ObjectIdentifier{ntlmOID}}
	initBytes, err := asn1.Marshal(init)
	if err != nil {
		return nil
	}
	oidBytes, err := asn1.Marshal(spnegoOID)
	if err != nil {
		return nil
	}
	inner := append(oidBytes, wrapDER(0xA0, initBytes)...)
	return wrapDER(0x60, inner)
})

func wrapSPNEGOChallenge(challenge []byte) ([]byte, error) {
	return wrapNegTokenResp(1, challenge)
}

func wrapSPNEGOAccept() ([]byte, error) {
	return wrapNegTokenResp(0, nil)
}

func wrapNegTokenResp(negState int, responseToken []byte) ([]byte, error) {
	resp := struct {
		NegState      asn1.Enumerated       `asn1:"explicit,tag:0"`
		SupportedMech asn1.ObjectIdentifier `asn1:"explicit,optional,tag:1"`
		ResponseToken []byte                `asn1:"explicit,optional,tag:2"`
	}{asn1.Enumerated(negState), ntlmOID, responseToken}
	respBytes, err := asn1.Marshal(resp)
	if err != nil {
		return nil, err
	}
	return wrapDER(0xA1, respBytes), nil
}

func wrapDER(tag byte, content []byte) []byte {
	out := append([]byte{tag}, derLength(len(content))...)
	return append(out, content...)
}

func derLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var buf []byte
	for n > 0 {
		buf = append([]byte{byte(n)}, buf...)
		n >>= 8
	}
	return append([]byte{0x80 | byte(len(buf))}, buf...)
}

func rc4Decrypt(key, ciphertext []byte) []byte {
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil
	}
	out := make([]byte, len(ciphertext))
	c.XORKeyStream(out, ciphertext)
	return out
}

func ctEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
