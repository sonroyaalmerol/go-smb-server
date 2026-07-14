package server

import (
	"context"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/sonroyaalmerol/go-smb-server/smb/ntlmssp"
	"github.com/sonroyaalmerol/go-smb-server/smb/vfs"
)

func countGoroutines() int { return runtime.NumGoroutine() }

func startTestServer(t *testing.T) (*Server, net.Listener, context.CancelFunc, <-chan struct{}) {
	t.Helper()
	backend := newMemBackend()
	creds := ntlmssp.NewMemoryCredentials()
	creds.Add("TEST", "alice", "secret")

	srv, err := New(
		WithShares(vfs.NewDiskShare("share", backend)),
		WithAuth(ntlmssp.NewServer(creds, "SRV")),
	)
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
	return srv, ln, func() {
		cancel()
		ln.Close()
		<-done
	}, done
}

func waitForGoroutineDrop(t *testing.T, baseline int) {
	t.Helper()
	for range 50 {
		runtime.GC()
		if countGoroutines() <= baseline+2 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("goroutine leak: baseline=%d, current=%d", baseline, countGoroutines())
}

func TestNoLeakOnDisconnect(t *testing.T) {
	_, ln, stop, _ := startTestServer(t)
	defer stop()

	before := countGoroutines()

	for range 5 {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conn.Close()
	}

	waitForGoroutineDrop(t, before)
}

func TestNoLeakOnGracefulShutdown(t *testing.T) {
	_, _, stop, _ := startTestServer(t)

	before := countGoroutines()
	stop()
	waitForGoroutineDrop(t, before)
}

func TestShutdownClosesListener(t *testing.T) {
	srv, err := New(
		WithShares(vfs.NewDiskShare("share", newMemBackend())),
		WithAddr("127.0.0.1:0"),
	)
	if err != nil {
		t.Fatal(err)
	}

	ctx := t.Context()

	var wg sync.WaitGroup
	wg.Go(func() {
		_ = srv.ListenAndServe(ctx)
	})

	time.Sleep(100 * time.Millisecond)
	if err := srv.Shutdown(); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	wg.Wait()
}
