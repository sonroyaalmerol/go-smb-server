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
	docsDir := flag.String("docs", "/tmp/smb-docs", "documents directory")
	mediaDir := flag.String("media", "/tmp/smb-media", "media directory")
	scratchDir := flag.String("scratch", "/tmp/smb-scratch", "scratch directory")
	flag.Parse()

	docsBackend, err := vfs.NewLocalBackend(*docsDir)
	if err != nil {
		slog.Error("open docs backend", "err", err)
		os.Exit(1)
	}

	mediaBackend, err := vfs.NewLocalBackend(*mediaDir)
	if err != nil {
		slog.Error("open media backend", "err", err)
		os.Exit(1)
	}

	scratchBackend, err := vfs.NewLocalBackend(*scratchDir)
	if err != nil {
		slog.Error("open scratch backend", "err", err)
		os.Exit(1)
	}

	creds := ntlmssp.NewMemoryCredentials()
	creds.Add("WORKGROUP", "alice", "secret")

	srv, err := server.New(
		server.WithAddr(*addr),
		server.WithShares(
			vfs.NewDiskShare("documents", docsBackend),
			vfs.NewDiskShare("media", mediaBackend),
			vfs.NewDiskShare("scratch", scratchBackend),
		),
		server.WithAuth(ntlmssp.NewServer(creds, "FILESRV")),
		server.WithLogger(slog.Default()),
	)
	if err != nil {
		slog.Error("new server", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	slog.Info("serving (multi-share)", "addr", *addr,
		"shares", []string{"documents", "media", "scratch"})
	if err := srv.ListenAndServe(ctx); err != nil {
		slog.Error("serve", "err", err)
		os.Exit(1)
	}
}
