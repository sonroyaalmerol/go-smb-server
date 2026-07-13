//go:build integration

package server

import (
	"context"
	"io"
	"net"
	"testing"

	client "github.com/hirochachacha/go-smb2"
	"github.com/sonroyaalmerol/go-smb-server/smb/auth"
	"github.com/sonroyaalmerol/go-smb-server/smb/ntlmssp"
	"github.com/sonroyaalmerol/go-smb-server/smb/vfs"
)

func startNTLMServer(t *testing.T) (addr string, backend *memBackend, stop func()) {
	return startNTLMServerOpt(t)
}

func startNTLMServerOpt(t *testing.T, srvOpts ...Option) (addr string, backend *memBackend, stop func()) {
	t.Helper()
	backend = newMemBackend()

	creds := ntlmssp.NewMemoryCredentials()
	creds.Add("TEST", "alice", "secret")

	srv, err := newServerWith(ntlmssp.NewServer(creds, "SRV"), backend, srvOpts...)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				close(done)
				return
			}
			go srv.serveConn(ctx, c)
		}
	}()
	stop = func() {
		cancel()
		_ = ln.Close()
		<-done
	}
	return ln.Addr().String(), backend, stop
}

func newServerWith(authFactory auth.Factory, backend vfs.Backend, opts ...Option) (*Server, error) {
	args := []Option{
		WithShares(vfs.NewDiskShare("share", backend)),
		WithAuth(authFactory),
	}
	args = append(args, opts...)
	return New(args...)
}

func TestIntegration_ReferenceClient(t *testing.T) {
	addr, _, stop := startNTLMServer(t)
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	d := &client.Dialer{
		Initiator: &client.NTLMInitiator{
			User:     "alice",
			Password: "secret",
			Domain:   "TEST",
		},
	}

	s, err := d.Dial(conn)
	if err != nil {
		t.Fatalf("dial/negotiate/session-setup: %v", err)
	}
	defer s.Logoff()

	fs, err := s.Mount("share")
	if err != nil {
		t.Fatalf("tree_connect share: %v", err)
	}
	defer fs.Umount()

	f, err := fs.Create("hello.txt")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	payload := []byte("Hello from the reference client!")
	if _, err := f.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	defer fs.Remove("hello.txt")

	f2, err := fs.Open("hello.txt")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	got, err := io.ReadAll(f2)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	f2.Close()
	if string(got) != string(payload) {
		t.Fatalf("roundtrip = %q, want %q", got, payload)
	}

	fi, err := fs.Stat("hello.txt")
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Size() != int64(len(payload)) {
		t.Fatalf("stat size = %d, want %d", fi.Size(), len(payload))
	}

	ents, err := fs.ReadDir("")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(ents) == 0 {
		t.Fatal("readdir returned no entries")
	}
}
