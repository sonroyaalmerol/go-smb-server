package ntlmssp

import (
	"crypto/hmac"
	"crypto/md5"
	"errors"
	"strings"

	"golang.org/x/crypto/md4"
)

var ntlmSignature = [8]byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00}

const (
	MsgNegotiate    uint32 = 0x00000001
	MsgChallenge    uint32 = 0x00000002
	MsgAuthenticate uint32 = 0x00000003
)

const (
	FlagNegotiateUnicode     uint32 = 0x00000001
	FlagNegotiateOEM         uint32 = 0x00000002
	FlagRequestTarget        uint32 = 0x00000004
	FlagNegotiateSign        uint32 = 0x00000010
	FlagNegotiateSeal        uint32 = 0x00000020
	FlagNegotiateLMKey       uint32 = 0x00000080
	FlagNegotiateNTLM        uint32 = 0x00000200
	FlagNegotiateAlwaysSign  uint32 = 0x00008000
	FlagNegotiateExtSecurity uint32 = 0x00080000
	FlagNegotiateTargetInfo  uint32 = 0x00800000
	FlagTargetTypeDomain     uint32 = 0x00010000
	FlagTargetTypeServer     uint32 = 0x00020000
	FlagTargetTypeShare      uint32 = 0x00040000
	FlagNegotiateVersion     uint32 = 0x02000000
	FlagNegotiate128         uint32 = 0x20000000
	FlagNegotiateKeyExch     uint32 = 0x40000000
	FlagNegotiate56          uint32 = 0x80000000
)

const serverChallengeFlags = FlagNegotiateUnicode |
	FlagRequestTarget |
	FlagNegotiateNTLM |
	FlagNegotiateSign |
	FlagNegotiateSeal |
	FlagNegotiateAlwaysSign |
	FlagNegotiateExtSecurity |
	FlagNegotiateTargetInfo |
	FlagNegotiate128 |
	FlagNegotiateVersion |
	FlagNegotiateKeyExch

func NTOWFv2(password, user, domain string) []byte {
	hash := md4.New()
	hash.Write([]byte(toUTF16LE(password)))
	ntHash := hash.Sum(nil)

	concat := strings.ToUpper(user) + domain
	key := []byte(toUTF16LE(concat))

	mac := hmac.New(md5.New, ntHash)
	mac.Write(key)
	return mac.Sum(nil)
}

func computeNTProofStr(responseKeyNT, serverChallenge, ntChallengeResponse []byte) []byte {
	temp := ntChallengeResponse[16:]
	mac := hmac.New(md5.New, responseKeyNT)
	mac.Write(serverChallenge)
	mac.Write(temp)
	return mac.Sum(nil)
}

func sessionBaseKey(responseKeyNT, ntProofStr []byte) []byte {
	mac := hmac.New(md5.New, responseKeyNT)
	mac.Write(ntProofStr)
	return mac.Sum(nil)
}

var ErrInvalidNTLMMessage = errors.New("ntlmssp: invalid NTLM message")

func toUTF16LE(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 2)
	for _, c := range s {
		v := uint16(c)
		b.WriteByte(byte(v))
		b.WriteByte(byte(v >> 8))
	}
	return b.String()
}
