package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/sonroyaalmerol/go-smb-server/smb/kerberos"
	"github.com/sonroyaalmerol/go-smb-server/smb/server"
	"github.com/sonroyaalmerol/go-smb-server/smb/vfs"
)

func main() {
	addr := flag.String("addr", ":445", "listen address")
	dir := flag.String("dir", "/tmp/smbshare", "directory to export")
	keytabPath := flag.String("keytab", "/etc/krb5.keytab", "path to service keytab")
	flag.Parse()

	backend, err := vfs.NewLocalBackend(*dir)
	if err != nil {
		slog.Error("open backend", "err", err)
		os.Exit(1)
	}

	kt, err := keytab.Load(*keytabPath)
	if err != nil {
		slog.Error("load keytab", "path", *keytabPath, "err", err)
		os.Exit(1)
	}

	srv, err := server.New(
		server.WithAddr(*addr),
		server.WithShares(vfs.NewDiskShare("share", backend)),
		server.WithAuth(kerberos.NewServer(kt)),
		server.WithLogger(slog.Default()),
	)
	if err != nil {
		slog.Error("new server", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	slog.Info("serving (Kerberos auth)", "addr", *addr, "dir", *dir, "keytab", *keytabPath)
	if err := srv.ListenAndServe(ctx); err != nil {
		slog.Error("serve", "err", err)
		os.Exit(1)
	}
}
