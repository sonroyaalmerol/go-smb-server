package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/sonroyaalmerol/go-smb-server/smb/auth"
	"github.com/sonroyaalmerol/go-smb-server/smb/ntlmssp"
	"github.com/sonroyaalmerol/go-smb-server/smb/server"
	"github.com/sonroyaalmerol/go-smb-server/smb/vfs"
)

func main() {
	addr := flag.String("addr", ":445", "listen address")
	dir := flag.String("dir", "/tmp/smbshare", "directory to export")
	flag.Parse()

	backend, err := vfs.NewLocalBackend(*dir)
	if err != nil {
		slog.Error("open backend", "err", err)
		os.Exit(1)
	}

	creds := ntlmssp.NewMemoryCredentials()
	creds.Add("WORKGROUP", "alice", "secret")
	creds.Add("WORKGROUP", "bob", "password123")

	relayFactory := func() auth.RelayFunc {
		upstream := ntlmssp.NewServer(creds, "FILESRV")()

		return func(_ context.Context, spnegoToken []byte) ([]byte, []byte, *auth.Identity, error) {
			result, err := upstream.Accept(context.Background(), spnegoToken)
			if err != nil {
				return nil, nil, nil, err
			}
			if result.Identity == nil {
				return result.OutputToken, nil, nil, nil
			}
			return result.OutputToken, result.SessionKey, result.Identity, nil
		}
	}

	srv, err := server.New(
		server.WithAddr(*addr),
		server.WithShares(vfs.NewDiskShare("share", backend)),
		server.WithAuth(auth.NewRelayAuthenticator(relayFactory)),
		server.WithLogger(slog.Default()),
	)
	if err != nil {
		slog.Error("new server", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	slog.Info("serving (relay auth)", "addr", *addr, "dir", *dir)
	if err := srv.ListenAndServe(ctx); err != nil {
		slog.Error("serve", "err", err)
		os.Exit(1)
	}
}
