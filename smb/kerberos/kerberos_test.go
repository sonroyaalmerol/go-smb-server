package kerberos_test

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	goforkasn1 "github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"

	"github.com/sonroyaalmerol/go-smb-server/smb/auth"
	"github.com/sonroyaalmerol/go-smb-server/smb/kerberos"
)

const (
	testRealm    = "TEST.GOKRB5"
	testClient   = "testuser1"
	testService  = "cifs/testserver"
	testPassword = "service-passphrase"
)

func newTestKeytab(t *testing.T) *keytab.Keytab {
	t.Helper()
	kt := keytab.New()
	if err := kt.AddEntry(testService, testRealm, testPassword, time.Now().UTC(), 1, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
		t.Fatalf("AddEntry: %v", err)
	}
	return kt
}

func testPrincipals() (cname, sname types.PrincipalName) {
	cname = types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{testClient}}
	sname = types.PrincipalName{NameType: nametype.KRB_NT_SRV_INST, NameString: []string{"cifs", "testserver"}}
	return cname, sname
}

func buildToken(t *testing.T, kt *keytab.Keytab, withSubkey bool) ([]byte, []byte) {
	t.Helper()
	cname, sname := testPrincipals()
	now := time.Now().UTC()

	tkt, sessionKey, err := messages.NewTicket(
		cname, testRealm, sname, testRealm,
		types.NewKrbFlags(), kt, etypeID.AES256_CTS_HMAC_SHA1_96, 1,
		now, now, now.Add(time.Hour), now.Add(24*time.Hour),
	)
	if err != nil {
		t.Fatalf("NewTicket: %v", err)
	}

	var mechToken []byte
	if !withSubkey {
		creds := credentials.New(testClient, testRealm)
		creds.SetCName(cname)
		cl := client.Client{Credentials: creds}
		mt, err := spnego.NewKRB5TokenAPREQ(&cl, tkt, sessionKey,
			[]int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}, nil)
		if err != nil {
			t.Fatalf("NewKRB5TokenAPREQ: %v", err)
		}
		mechToken, err = mt.Marshal()
		if err != nil {
			t.Fatalf("marshal KRB5Token: %v", err)
		}
	} else {
		authn, err := types.NewAuthenticator(testRealm, cname)
		if err != nil {
			t.Fatalf("NewAuthenticator: %v", err)
		}
		chksum := make([]byte, 24)
		binary.LittleEndian.PutUint32(chksum[0:4], 16)
		binary.LittleEndian.PutUint32(chksum[20:24],
			uint32(gssapi.ContextFlagInteg|gssapi.ContextFlagConf))
		authn.Cksum = types.Checksum{CksumType: chksumtype.GSSAPI, Checksum: chksum}
		if err := authn.GenerateSeqNumberAndSubKey(etypeID.AES256_CTS_HMAC_SHA1_96, 32); err != nil {
			t.Fatalf("GenerateSeqNumberAndSubKey: %v", err)
		}
		apreq, err := messages.NewAPReq(tkt, sessionKey, authn)
		if err != nil {
			t.Fatalf("NewAPReq: %v", err)
		}
		oidBytes, _ := goforkasn1.Marshal(gssapi.OIDKRB5.OID())
		b := append(oidBytes, 0x01, 0x00)
		apreqBytes, err := apreq.Marshal()
		if err != nil {
			t.Fatalf("marshal APReq: %v", err)
		}
		b = append(b, apreqBytes...)
		mechToken = asn1tools.AddASNAppTag(b, 0)
	}

	negInit := spnego.NegTokenInit{
		MechTypes:      []goforkasn1.ObjectIdentifier{gssapi.OIDKRB5.OID()},
		MechTokenBytes: mechToken,
	}
	st := spnego.SPNEGOToken{Init: true, NegTokenInit: negInit}
	token, err := st.Marshal()
	if err != nil {
		t.Fatalf("marshal SPNEGO: %v", err)
	}

	expectedKey := sessionKey.KeyValue
	if withSubkey {
		expectedKey = nil
	}
	return token, expectedKey
}

func TestAuthenticator_AcceptSuccess(t *testing.T) {
	kt := newTestKeytab(t)
	token, expectedKey := buildToken(t, kt, false)

	a := kerberos.NewServer(kt)()
	res, err := a.Accept(context.Background(), token)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if res.Identity == nil {
		t.Fatal("nil identity")
	}
	if res.Identity.Username != testClient {
		t.Errorf("username = %q, want %q", res.Identity.Username, testClient)
	}
	if res.Identity.Domain != testRealm {
		t.Errorf("domain = %q, want %q", res.Identity.Domain, testRealm)
	}
	if len(res.SessionKey) != len(expectedKey) {
		t.Fatalf("session key len = %d, want %d", len(res.SessionKey), len(expectedKey))
	}
	for i := range res.SessionKey {
		if res.SessionKey[i] != expectedKey[i] {
			t.Fatalf("session key mismatch at byte %d", i)
		}
	}
}

func TestAuthenticator_AcceptUsesInitiatorSubkey(t *testing.T) {
	kt := newTestKeytab(t)
	token, _ := buildToken(t, kt, false)
	tokenSub, _ := buildToken(t, kt, true)

	base := kerberos.NewServer(kt)()
	r1, err := base.Accept(context.Background(), token)
	if err != nil {
		t.Fatalf("Accept no-subkey: %v", err)
	}

	sub := kerberos.NewServer(kt)()
	r2, err := sub.Accept(context.Background(), tokenSub)
	if err != nil {
		t.Fatalf("Accept subkey: %v", err)
	}
	if len(r2.SessionKey) != 32 {
		t.Fatalf("subkey session key len = %d, want 32", len(r2.SessionKey))
	}
	if equalBytes(r1.SessionKey, r2.SessionKey) {
		t.Fatal("subkey path exported the ticket session key; expected the initiator subkey")
	}
}

func TestAuthenticator_OutputTokenIsAcceptCompleted(t *testing.T) {
	kt := newTestKeytab(t)
	token, _ := buildToken(t, kt, false)

	a := kerberos.NewServer(kt)()
	res, err := a.Accept(context.Background(), token)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if len(res.OutputToken) == 0 {
		t.Fatal("no output token")
	}
	var resp spnego.SPNEGOToken
	if err := resp.Unmarshal(res.OutputToken); err != nil {
		t.Fatalf("unmarshal response token: %v", err)
	}
	if !resp.Resp {
		t.Fatal("response is not a NegTokenResp")
	}
	if got := resp.NegTokenResp.State(); got != spnego.NegStateAcceptCompleted {
		t.Errorf("negState = %d, want %d (accept-completed)", got, spnego.NegStateAcceptCompleted)
	}
}

func TestAuthenticator_RejectsGarbage(t *testing.T) {
	kt := newTestKeytab(t)
	a := kerberos.NewServer(kt)()
	if _, err := a.Accept(context.Background(), []byte{0xDE, 0xAD, 0xBE, 0xEF}); !errors.Is(err, auth.ErrLogonFailed) {
		t.Fatalf("err = %v, want ErrLogonFailed", err)
	}
	if _, err := a.Accept(context.Background(), nil); !errors.Is(err, auth.ErrLogonFailed) {
		t.Fatalf("err = %v, want ErrLogonFailed", err)
	}
}

func TestAuthenticator_RejectsNTLMMech(t *testing.T) {
	kt := newTestKeytab(t)
	ntlmOID := goforkasn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}
	negInit := spnego.NegTokenInit{
		MechTypes:      []goforkasn1.ObjectIdentifier{ntlmOID},
		MechTokenBytes: []byte("NTLMSSP\x00"),
	}
	st := spnego.SPNEGOToken{Init: true, NegTokenInit: negInit}
	token, err := st.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	a := kerberos.NewServer(kt)()
	if _, err := a.Accept(context.Background(), token); !errors.Is(err, auth.ErrLogonFailed) {
		t.Fatalf("err = %v, want ErrLogonFailed", err)
	}
}

func TestAuthenticator_RejectsTamperedToken(t *testing.T) {
	kt := newTestKeytab(t)
	token, _ := buildToken(t, kt, false)
	if len(token) > 40 {
		token[len(token)-1] ^= 0xFF
	}
	a := kerberos.NewServer(kt)()
	if _, err := a.Accept(context.Background(), token); !errors.Is(err, auth.ErrLogonFailed) {
		t.Fatalf("err = %v, want ErrLogonFailed", err)
	}
}

func TestAuthenticator_RejectsWrongKeytab(t *testing.T) {
	good := newTestKeytab(t)
	token, _ := buildToken(t, good, false)

	other := keytab.New()
	if err := other.AddEntry("cifs/other", testRealm, "different-pass", time.Now().UTC(), 1, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
		t.Fatalf("AddEntry: %v", err)
	}
	a := kerberos.NewServer(other)()
	if _, err := a.Accept(context.Background(), token); !errors.Is(err, auth.ErrLogonFailed) {
		t.Fatalf("err = %v, want ErrLogonFailed", err)
	}
}

func TestAuthenticator_RejectsExpiredTicket(t *testing.T) {
	kt := newTestKeytab(t)
	cname, sname := testPrincipals()
	now := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(
		cname, testRealm, sname, testRealm,
		types.NewKrbFlags(), kt, etypeID.AES256_CTS_HMAC_SHA1_96, 1,
		now.Add(-2*time.Hour), now.Add(-2*time.Hour), now.Add(-time.Hour), now.Add(-time.Hour),
	)
	if err != nil {
		t.Fatalf("NewTicket: %v", err)
	}
	creds := credentials.New(testClient, testRealm)
	creds.SetCName(cname)
	cl := client.Client{Credentials: creds}
	mt, err := spnego.NewKRB5TokenAPREQ(&cl, tkt, sessionKey,
		[]int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}, nil)
	if err != nil {
		t.Fatalf("NewKRB5TokenAPREQ: %v", err)
	}
	mech, err := mt.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	negInit := spnego.NegTokenInit{
		MechTypes:      []goforkasn1.ObjectIdentifier{gssapi.OIDKRB5.OID()},
		MechTokenBytes: mech,
	}
	st := spnego.SPNEGOToken{Init: true, NegTokenInit: negInit}
	token, err := st.Marshal()
	if err != nil {
		t.Fatalf("marshal SPNEGO: %v", err)
	}
	a := kerberos.NewServer(kt)()
	if _, err := a.Accept(context.Background(), token); !errors.Is(err, auth.ErrLogonFailed) {
		t.Fatalf("err = %v, want ErrLogonFailed", err)
	}
}

func TestAuthenticator_RawKRB5Token(t *testing.T) {
	kt := newTestKeytab(t)
	creds := credentials.New(testClient, testRealm)
	cname, sname := testPrincipals()
	creds.SetCName(cname)
	now := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(
		cname, testRealm, sname, testRealm,
		types.NewKrbFlags(), kt, etypeID.AES256_CTS_HMAC_SHA1_96, 1,
		now, now, now.Add(time.Hour), now.Add(24*time.Hour),
	)
	if err != nil {
		t.Fatalf("NewTicket: %v", err)
	}
	cl := client.Client{Credentials: creds}
	mt, err := spnego.NewKRB5TokenAPREQ(&cl, tkt, sessionKey,
		[]int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}, nil)
	if err != nil {
		t.Fatalf("NewKRB5TokenAPREQ: %v", err)
	}
	raw, err := mt.Marshal()
	if err != nil {
		t.Fatalf("marshal raw KRB5Token: %v", err)
	}
	a := kerberos.NewServer(kt)()
	res, err := a.Accept(context.Background(), raw)
	if err != nil {
		t.Fatalf("Accept raw token: %v", err)
	}
	if res.Identity == nil || res.Identity.Username != testClient {
		t.Fatalf("identity = %+v", res.Identity)
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
