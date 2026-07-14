package main

import (
	"context"
	"encoding/json"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/sonroyaalmerol/go-smb-server/smb/ntlmssp"
	"github.com/sonroyaalmerol/go-smb-server/smb/server"
	"github.com/sonroyaalmerol/go-smb-server/smb/vfs"
)

type userEntry struct {
	Domain   string `json:"domain"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type fileLookup struct {
	users []userEntry
}

func (f *fileLookup) LookupNTOWFv2(_ context.Context, domain, user string) ([]byte, error) {
	for _, u := range f.users {
		if strings.EqualFold(u.Domain, domain) && strings.EqualFold(u.Username, user) {
			return ntlmssp.NTOWFv2(u.Password, u.Username, u.Domain), nil
		}
	}
	return nil, ntlmssp.ErrUnknownUser
}

func main() {
	addr := flag.String("addr", ":445", "listen address")
	dir := flag.String("dir", "/tmp/smbshare", "directory to export")
	usersFile := flag.String("users", "users.json", "JSON file with user credentials")
	flag.Parse()

	backend, err := vfs.NewLocalBackend(*dir)
	if err != nil {
		slog.Error("open backend", "err", err)
		os.Exit(1)
	}

	raw, err := os.ReadFile(*usersFile)
	if err != nil {
		slog.Error("read users file", "err", err, "file", *usersFile)
		os.Exit(1)
	}

	var users []userEntry
	if err := json.Unmarshal(raw, &users); err != nil {
		slog.Error("parse users file", "err", err)
		os.Exit(1)
	}

	lookup := &fileLookup{users: users}

	srv, err := server.New(
		server.WithAddr(*addr),
		server.WithShares(vfs.NewDiskShare("share", backend)),
		server.WithAuth(ntlmssp.NewServer(lookup, "FILESRV")),
		server.WithLogger(slog.Default()),
	)
	if err != nil {
		slog.Error("new server", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	slog.Info("serving (custom auth)", "addr", *addr, "dir", *dir, "users", len(users))
	if err := srv.ListenAndServe(ctx); err != nil {
		slog.Error("serve", "err", err)
		os.Exit(1)
	}
}
