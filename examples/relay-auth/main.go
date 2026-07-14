package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/sonroyaalmerol/go-smb-server/smb/auth"
	"github.com/sonroyaalmerol/go-smb-server/smb/server"
	"github.com/sonroyaalmerol/go-smb-server/smb/vfs"
)

func main() {
	addr := flag.String("addr", ":445", "listen address")
	dir := flag.String("dir", "/tmp/smbshare", "directory to export")
	upstream := flag.String("upstream", "", "upstream NTLM auth service (host:port)")
	flag.Parse()

	backend, err := vfs.NewLocalBackend(*dir)
	if err != nil {
		slog.Error("open backend", "err", err)
		os.Exit(1)
	}

	relay := func(ctx context.Context, spnegoToken []byte) ([]byte, []byte, *auth.Identity, error) {
		if *upstream == "" {
			return nil, nil, nil, auth.ErrLogonFailed
		}

		conn, err := net.DialTimeout("tcp", *upstream, 5e9)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("relay: connect upstream: %w", err)
		}
		defer conn.Close()

		return nil, nil, nil, auth.ErrLogonFailed
	}

	srv, err := server.New(
		server.WithAddr(*addr),
		server.WithShares(vfs.NewDiskShare("share", backend)),
		server.WithAuth(auth.NewRelayAuthenticator(relay)),
		server.WithLogger(slog.Default()),
	)
	if err != nil {
		slog.Error("new server", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	slog.Info("serving (relay auth)", "addr", *addr, "dir", *dir, "upstream", *upstream)
	if err := srv.ListenAndServe(ctx); err != nil {
		slog.Error("serve", "err", err)
		os.Exit(1)
	}
}
