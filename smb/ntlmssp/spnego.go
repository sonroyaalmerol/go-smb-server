package ntlmssp

import (
	"crypto/rc4"
	"crypto/subtle"
	"encoding/asn1"
	"errors"
	"fmt"
)

var spnegoOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 2}


func UnwrapSPNEGOToken(token []byte) ([]byte, error) {
	if isNTLMSSP(token) {
		return token, nil
	}
	var ict struct {
		OID  asn1.ObjectIdentifier
		Rest asn1.RawValue
	}
	if _, err := asn1.Unmarshal(token, &ict); err == nil && ict.OID.Equal(spnegoOID) {
		if ntlm, ok := findContextTag2(ict.Rest.Bytes); ok && isNTLMSSP(ntlm) {
			return ntlm, nil
		}
	}
	if ntlm, ok := findContextTag2(token); ok && isNTLMSSP(ntlm) {
		return ntlm, nil
	}
	return nil, fmt.Errorf("spnego: could not locate NTLMSSP token")
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

func isNTLMSSP(b []byte) bool { return len(b) >= 8 && [8]byte(b[0:8]) == Signature }

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

func WrapSPNEGOChallenge(challenge []byte) ([]byte, error) {
	negResult := derContextTag(0xA0, []byte{0x01})
	supportedMech, err := asn1.Marshal(spnegoOID)
	if err != nil {
		return nil, err
	}
	supportedMech[0] = 0xA1
	responseToken := derContextTagOctetString(0xA2, challenge)

	inner := append(append(negResult, supportedMech...), responseToken...)
	targ := wrapDER(0x30, inner)
	return targ, nil
}

func derContextTag(tag byte, content []byte) []byte {
	return wrapDER(tag, content)
}

func derContextTagOctetString(tag byte, content []byte) []byte {
	return wrapDER(tag, wrapDER(0x04, content))
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
