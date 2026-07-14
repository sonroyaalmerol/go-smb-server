package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"

	"github.com/sonroyaalmerol/go-smb-server/smb/kerberos"
	"github.com/sonroyaalmerol/go-smb-server/smb/signing"
	"github.com/sonroyaalmerol/go-smb-server/smb/transport"
	"github.com/sonroyaalmerol/go-smb-server/smb/vfs"
	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

const (
	intRealm    = "SMBTEST.TEST"
	intUser     = "testuser1"
	intUserPass = "userpw"
	intService  = "cifs/testserver"
)

func requireBin(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("krb5 binary %q not found: %v", name, err)
	}
	return p
}

type kdcEnv struct {
	dir      string
	realm    string
	port     int
	krb5Conf string
	kdcConf  string
	database string
	keytab   string
	kdcCmd   *exec.Cmd
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

func startKDC(t *testing.T, servicePrincipals ...string) (*kdcEnv, *keytab.Keytab) {
	t.Helper()
	for _, b := range []string{"krb5kdc", "kadmin.local", "kdb5_util"} {
		requireBin(t, b)
	}
	if len(servicePrincipals) == 0 {
		servicePrincipals = []string{intService}
	}

	dir := t.TempDir()
	port := freePort(t)
	db := filepath.Join(dir, "principal")
	stash := filepath.Join(dir, "stash")
	acl := filepath.Join(dir, "kadm5.acl")
	krb5Conf := filepath.Join(dir, "krb5.conf")
	kdcConf := filepath.Join(dir, "kdc.conf")
	ktPath := filepath.Join(dir, "service.keytab")

	if err := os.WriteFile(acl, nil, 0o600); err != nil {
		t.Fatalf("write acl: %v", err)
	}
	krb5Body := fmt.Sprintf(`[libdefaults]
	default_realm = %s
	dns_lookup_kdc = false
	rdns = false
	ignore_acceptor_hostname = true
	udp_preference_limit = 1

[realms]
	%s = {
		kdc = 127.0.0.1:%d
	}
`, intRealm, intRealm, port)
	if err := os.WriteFile(krb5Conf, []byte(krb5Body), 0o600); err != nil {
		t.Fatalf("write krb5.conf: %v", err)
	}
	kdcBody := fmt.Sprintf(`[kdcdefaults]
	kdc_ports = %d
	kdc_tcp_ports = %d

[realms]
	%s = {
		database_name = %s
		acl_file = %s
		key_stash_file = %s
	}

[logging]
	kdc = FILE:%s/kdc.log
`, port, port, intRealm, db, acl, stash, dir)
	if err := os.WriteFile(kdcConf, []byte(kdcBody), 0o600); err != nil {
		t.Fatalf("write kdc.conf: %v", err)
	}

	run := func(name string, args ...string) {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Env = append(os.Environ(),
			"KRB5_CONFIG="+krb5Conf,
			"KRB5_KDC_PROFILE="+kdcConf,
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
		}
	}
	adminQ := func(q string) {
		t.Helper()
		cmd := exec.Command("kadmin.local", "-d", db, "-r", intRealm, "-q", q)
		cmd.Env = append(os.Environ(), "KRB5_CONFIG="+krb5Conf, "KRB5_KDC_PROFILE="+kdcConf)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("kadmin.local %q: %v\n%s", q, err, out)
		}
	}

	run("kdb5_util", "-r", intRealm, "create", "-s", "-P", "master-key", "-W")
	adminQ(fmt.Sprintf("addprinc -pw %s %s", intUserPass, intUser))
	for _, spn := range servicePrincipals {
		adminQ(fmt.Sprintf("addprinc -pw svcpw %s", spn))
		adminQ(fmt.Sprintf("ktadd -k %s %s", ktPath, spn))
	}

	kdc := exec.Command("krb5kdc", "-n", "-r", intRealm)
	kdc.Env = append(os.Environ(), "KRB5_KDC_PROFILE="+kdcConf)
	if err := kdc.Start(); err != nil {
		t.Fatalf("start krb5kdc: %v", err)
	}
	t.Cleanup(func() {
		_ = kdc.Process.Kill()
		_, _ = kdc.Process.Wait()
	})
	if err := waitForKDC(port); err != nil {
		t.Fatalf("KDC did not become ready: %v", err)
	}

	kt, err := keytab.Load(ktPath)
	if err != nil {
		t.Fatalf("load keytab: %v", err)
	}
	env := &kdcEnv{
		dir: dir, realm: intRealm, port: port,
		krb5Conf: krb5Conf, kdcConf: kdcConf,
		database: db, keytab: ktPath, kdcCmd: kdc,
	}
	return env, kt
}

func waitForKDC(port int) error {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("timeout")
}

func TestKerberos_RealKDC_Gokrb5Client(t *testing.T) {
	env, kt := startKDC(t, intService)

	cfg, err := config.Load(env.krb5Conf)
	if err != nil {
		t.Fatalf("gokrb5 config.Load: %v", err)
	}
	cl := client.NewWithPassword(intUser, env.realm, intUserPass, cfg)
	if err := cl.Login(); err != nil {
		t.Fatalf("client AS-REQ (Login): %v", err)
	}
	tkt, sessKey, err := cl.GetServiceTicket(intService)
	if err != nil {
		t.Fatalf("client TGS-REQ (GetServiceTicket): %v", err)
	}
	if tkt.SName.NameString[0] != "cifs" {
		t.Fatalf("ticket SName = %v", tkt.SName)
	}
	if len(sessKey.KeyValue) == 0 {
		t.Fatal("no session key from TGS")
	}
	sp := spnego.SPNEGOClient(cl, intService)
	if err := sp.AcquireCred(); err != nil {
		t.Fatalf("AcquireCred: %v", err)
	}
	tok, err := sp.InitSecContext()
	if err != nil {
		t.Fatalf("InitSecContext: %v", err)
	}
	clientToken, err := tok.Marshal()
	if err != nil {
		t.Fatalf("marshal client SPNEGO token: %v", err)
	}
	if len(clientToken) == 0 {
		t.Fatal("empty client token")
	}

	srv, err := New(
		WithAuth(kerberos.NewServer(kt)),
		WithShares(vfs.NewDiskShare("share", newMemBackend())),
		WithLogger(discardLogger()),
	)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	clientConn, srvConn := newPipeConns()
	defer func() { _ = clientConn.Close() }()
	defer serveOn(srv, srvConn)()

	fc := transport.NewFramedConn(clientConn)
	negotiate(t, fc)

	mustWrite(t, fc, buildSessionSetup(clientToken))
	rh, _ := readReply(t, fc.Underlying())
	if rh.Status != wire.StatusSuccess {
		t.Fatalf("SESSION_SETUP with real Kerberos token: status %x", rh.Status)
	}
	if rh.SessionId == 0 {
		t.Fatal("no session id assigned")
	}
	sessID := rh.SessionId

	signKey := signing.DeriveSigningKey(sessKey.KeyValue)

	mustWrite(t, fc, signedTreeConnect(sessID, 2, `\\server\share`, signKey))
	rh, _ = readReply(t, fc.Underlying())
	if rh.Status != wire.StatusSuccess {
		t.Fatalf("signed TREE_CONNECT with real Kerberos session key: status %x", rh.Status)
	}

	mustWrite(t, fc, signedTreeConnect(sessID, 9, `\\server\share`, signing.DeriveSigningKey(make([]byte, 32))))
	rh, _ = readReply(t, fc.Underlying())
	if rh.Status == wire.StatusSuccess {
		t.Fatal("TREE_CONNECT signed with wrong key was accepted")
	}
}

var _ = context.Background
