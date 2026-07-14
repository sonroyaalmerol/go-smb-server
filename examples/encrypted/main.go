package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

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

	srv, err := server.New(
		server.WithAddr(*addr),
		server.WithShares(vfs.NewDiskShare("share", backend)),
		server.WithAuth(ntlmssp.NewServer(creds, "FILESRV")),
		server.WithEncryptionRequired(),
		server.WithLogger(slog.Default()),
	)
	if err != nil {
		slog.Error("new server", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	slog.Info("serving (encrypted)", "addr", *addr, "dir", *dir)
	if err := srv.ListenAndServe(ctx); err != nil {
		slog.Error("serve", "err", err)
		os.Exit(1)
	}
}
