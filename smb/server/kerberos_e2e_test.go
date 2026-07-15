package server

import (
	"encoding/binary"
	"testing"
	"time"

	goforkasn1 "github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"

	"github.com/sonroyaalmerol/go-smb-server/smb/kerberos"
	"github.com/sonroyaalmerol/go-smb-server/smb/signing"
	"github.com/sonroyaalmerol/go-smb-server/smb/transport"
	"github.com/sonroyaalmerol/go-smb-server/smb/vfs"
	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

const (
	kerbTestRealm   = "TEST.GOKRB5"
	kerbTestClient  = "testuser1"
	kerbTestService = "cifs/testserver"
	kerbTestPass    = "service-passphrase"
)

func newKerbTestKeytab(t *testing.T) *keytab.Keytab {
	t.Helper()
	kt := keytab.New()
	if err := kt.AddEntry(kerbTestService, kerbTestRealm, kerbTestPass, time.Now().UTC(), 1, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
		t.Fatalf("AddEntry: %v", err)
	}
	return kt
}

func buildKerbToken(t *testing.T, kt *keytab.Keytab) ([]byte, []byte) {
	t.Helper()
	cname := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{kerbTestClient}}
	sname := types.PrincipalName{NameType: nametype.KRB_NT_SRV_INST, NameString: []string{"cifs", "testserver"}}
	now := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(
		cname, kerbTestRealm, sname, kerbTestRealm,
		types.NewKrbFlags(), kt, etypeID.AES256_CTS_HMAC_SHA1_96, 1,
		now, now, now.Add(time.Hour), now.Add(24*time.Hour),
	)
	if err != nil {
		t.Fatalf("NewTicket: %v", err)
	}
	creds := credentials.New(kerbTestClient, kerbTestRealm)
	creds.SetCName(cname)
	cl := client.Client{Credentials: creds}
	mt, err := spnego.NewKRB5TokenAPREQ(&cl, tkt, sessionKey,
		[]int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}, nil)
	if err != nil {
		t.Fatalf("NewKRB5TokenAPREQ: %v", err)
	}
	mech, err := mt.Marshal()
	if err != nil {
		t.Fatalf("marshal KRB5Token: %v", err)
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
	return token, sessionKey.KeyValue
}

func newKerbTestServer(t *testing.T, backend vfs.Backend, kt *keytab.Keytab) *Server {
	t.Helper()
	srv, err := New(
		WithAuth(kerberos.NewServer(kt)),
		WithShares(vfs.NewDiskShare("share", backend)),
		WithLogger(discardLogger()),
	)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return srv
}

func signedTreeConnect(sessID uint64, msgID uint64, share string, signKey []byte) []byte {
	pathBytes := wire.UTF16ToBytes(share)
	hdr := wire.NewHeader(wire.CmdTreeConnect)
	hdr.SessionId = sessID
	hdr.MessageId = msgID
	hdr.Credit = 1
	hdr.Flags = wire.FlagSigned
	body := make([]byte, 8+len(pathBytes))
	binary.LittleEndian.PutUint16(body[0:2], 9)
	binary.LittleEndian.PutUint16(body[4:6], uint16(wire.HeaderSize+8))
	binary.LittleEndian.PutUint16(body[6:8], uint16(len(pathBytes)))
	copy(body[8:], pathBytes)
	m := hdr.Append(nil)
	m = append(m, body...)
	_ = signing.Sign(m, signKey, signing.AlgoAESCMAC)
	return m
}

func TestKerberosE2E_SessionSetupAndSigning(t *testing.T) {
	kt := newKerbTestKeytab(t)
	token, sessionKey := buildKerbToken(t, kt)

	client, srvConn := newPipeConns()
	defer client.Close()
	defer serveOn(newKerbTestServer(t, newMemBackend(), kt), srvConn)()

	fc := transport.NewFramedConn(client)

	negBody := make([]byte, 38)
	binary.LittleEndian.PutUint16(negBody[0:2], 36)
	binary.LittleEndian.PutUint16(negBody[2:4], 1)
	binary.LittleEndian.PutUint16(negBody[36:38], wire.DialectSMB302)
	hdr := wire.NewHeader(wire.CmdNegotiate)
	hdr.MessageId = 0
	hdr.Credit = 1
	mustWrite(t, fc, append(hdr.Append(nil), negBody...))
	rh, _ := readReply(t, fc)
	if rh.Status != wire.StatusSuccess {
		t.Fatalf("negotiate: %x", rh.Status)
	}

	mustWrite(t, fc, buildSessionSetup(token))
	rh, _ = readReply(t, fc)
	if rh.Status != wire.StatusSuccess {
		t.Fatalf("session_setup: %x", rh.Status)
	}
	if rh.SessionId == 0 {
		t.Fatal("session id not assigned")
	}
	sessID := rh.SessionId

	correctSigningKey := signing.DeriveSigningKey(sessionKey)
	mustWrite(t, fc, signedTreeConnect(sessID, 2, `\\server\share`, correctSigningKey))
	rh, _ = readReply(t, fc)
	if rh.Status != wire.StatusSuccess {
		t.Fatalf("signed tree_connect with correct key: %x", rh.Status)
	}

	wrongKey := signing.DeriveSigningKey(make([]byte, 32))
	mustWrite(t, fc, signedTreeConnect(sessID, 8, `\\server\share`, wrongKey))
	rh, _ = readReply(t, fc)
	if rh.Status == wire.StatusSuccess {
		t.Fatal("tree_connect signed with wrong key was accepted")
	}
}

func TestKerberosE2E_RejectsBadToken(t *testing.T) {
	kt := newKerbTestKeytab(t)
	client, srvConn := newPipeConns()
	defer client.Close()
	defer serveOn(newKerbTestServer(t, newMemBackend(), kt), srvConn)()

	fc := transport.NewFramedConn(client)

	negBody := make([]byte, 38)
	binary.LittleEndian.PutUint16(negBody[0:2], 36)
	binary.LittleEndian.PutUint16(negBody[2:4], 1)
	binary.LittleEndian.PutUint16(negBody[36:38], wire.DialectSMB302)
	hdr := wire.NewHeader(wire.CmdNegotiate)
	hdr.MessageId = 0
	hdr.Credit = 1
	mustWrite(t, fc, append(hdr.Append(nil), negBody...))
	rh, _ := readReply(t, fc)
	if rh.Status != wire.StatusSuccess {
		t.Fatalf("negotiate: %x", rh.Status)
	}

	mustWrite(t, fc, buildSessionSetup([]byte{0xDE, 0xAD, 0xBE, 0xEF}))
	rh, _ = readReply(t, fc)
	if rh.Status != wire.StatusLogonFailure {
		t.Fatalf("session_setup with garbage: status %x, want LOGON_FAILURE", rh.Status)
	}
}
