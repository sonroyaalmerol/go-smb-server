package ntlmssp

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"testing"
	"time"
)

type staticLookup struct {
	keys map[string][]byte
}

func (s *staticLookup) LookupNTOWFv2(_ context.Context, domain, user string) ([]byte, error) {
	if k, ok := s.keys[domain+"\\"+user]; ok {
		return k, nil
	}
	return nil, ErrUnknownUser
}

func buildAuthenticateClient(t *testing.T, password, user, domain string, serverChallenge [8]byte) []byte {
	t.Helper()
	responseKey := NTOWFv2(password, user, domain)

	var clientChallenge [8]byte
	if _, err := rand.Read(clientChallenge[:]); err != nil {
		t.Fatal(err)
	}
	now := uint64(time.Now().UnixNano())
	timeFile := filetimeFromUnix(now)

	targetInfo := []byte{0x00, 0x00, 0x00, 0x00}

	temp := make([]byte, 0, 2+6+8+8+4+len(targetInfo)+4)
	temp = append(temp, 0x01)
	temp = append(temp, 0x01)
	temp = append(temp, make([]byte, 6)...)
	temp = append(temp, timeFile[:]...)
	temp = append(temp, clientChallenge[:]...)
	temp = append(temp, make([]byte, 4)...)
	temp = append(temp, targetInfo...)
	temp = append(temp, make([]byte, 4)...)

	mac := hmac.New(md5.New, responseKey)
	mac.Write(serverChallenge[:])
	mac.Write(temp)
	proof := mac.Sum(nil)
	ntChallengeResponse := append(proof, temp...)

	return marshalAuthenticate(domain, user, serverChallenge, ntChallengeResponse)
}

func marshalAuthenticate(domain, user string, serverChallenge [8]byte, ntResp []byte) []byte {
	domainU := []byte(toUTF16LE(domain))
	userU := []byte(toUTF16LE(user))
	wksU := []byte(toUTF16LE("TESTWKS"))
	const fixed = 88
	payload := append([]byte(nil), domainU...)
	payload = append(payload, userU...)
	payload = append(payload, wksU...)
	payload = append(payload, ntResp...)

	out := make([]byte, fixed+len(payload))
	copy(out[0:8], ntlmSignature[:])
	binary.LittleEndian.PutUint32(out[8:12], MsgAuthenticate)
	putField(out[20:28], len(ntResp), fixed+len(domainU)+len(userU)+len(wksU))
	putField(out[28:36], len(domainU), fixed)
	putField(out[36:44], len(userU), fixed+len(domainU))
	putField(out[44:52], len(wksU), fixed+len(domainU)+len(userU))
	binary.LittleEndian.PutUint32(out[60:64], serverChallengeFlags)
	copy(out[fixed:], payload)
	return out
}

func putField(b []byte, length, offset int) {
	binary.LittleEndian.PutUint16(b[0:2], uint16(length))
	binary.LittleEndian.PutUint16(b[2:4], uint16(length))
	binary.LittleEndian.PutUint32(b[4:8], uint32(offset))
}

func filetimeFromUnix(unixNanos uint64) [8]byte {
	const ticksPerNS = uint64(10)
	const unixEpochFiletime = 116_444_736_000_000_000
	ft := unixEpochFiletime + (unixNanos/100)*ticksPerNS/10
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], ft)
	return b
}

func TestNTLMv2Handshake(t *testing.T) {
	const password = "correct horse battery staple"
	const user = "alice"
	const domain = "TEST"

	key := NTOWFv2(password, user, domain)
	lookup := &staticLookup{keys: map[string][]byte{domain + "\\" + user: key}}

	srv := NewServer(lookup, "SRV")().(*serverAuthenticator)

	if _, err := rand.Read(srv.challenge[:]); err != nil {
		t.Fatal(err)
	}
	srv.stage = 1

	authMsg := buildAuthenticateClient(t, password, user, domain, srv.challenge)
	res, err := srv.Accept(context.Background(), authMsg)
	if err != nil {
		t.Fatalf("server rejected valid credentials: %v", err)
	}
	if res.Identity == nil || res.Identity.Username != user {
		t.Fatalf("identity = %+v", res.Identity)
	}
	if len(res.SessionKey) != 16 {
		t.Fatalf("session key len = %d, want 16", len(res.SessionKey))
	}
}

func TestNTLMv2WrongPassword(t *testing.T) {
	key := NTOWFv2("right-password", "bob", "TEST")
	lookup := &staticLookup{keys: map[string][]byte{"TEST\\bob": key}}

	srv := NewServer(lookup, "SRV")().(*serverAuthenticator)
	if _, err := rand.Read(srv.challenge[:]); err != nil {
		t.Fatal(err)
	}
	srv.stage = 1

	authMsg := buildAuthenticateClient(t, "wrong-password", "bob", "TEST", srv.challenge)
	_, err := srv.Accept(context.Background(), authMsg)
	if err == nil {
		t.Fatal("server accepted wrong password")
	}
}

func TestNTOWFv2KnownVector(t *testing.T) {
	k1 := NTOWFv2("pw", "u", "D")
	k2 := NTOWFv2("pw", "u", "D")
	k3 := NTOWFv2("other", "u", "D")
	if len(k1) != 16 {
		t.Fatalf("NTOWFv2 len = %d, want 16", len(k1))
	}
	if string(k1) != string(k2) {
		t.Fatal("NTOWFv2 not deterministic")
	}
	if string(k1) == string(k3) {
		t.Fatal("NTOWFv2 collision across passwords")
	}
}
