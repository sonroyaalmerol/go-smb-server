package server

import (
	"strings"
	"testing"

	"github.com/sonroyaalmerol/go-smb-server/smb/auth"
	"github.com/sonroyaalmerol/go-smb-server/smb/vfs"
)

// TestNewRequiresAuthentication prevents accidental exposure of shares
// when an application omits its authentication configuration.
func TestNewRequiresAuthentication(t *testing.T) {
	share := vfs.NewDiskShare("share", newMemBackend())

	for _, tc := range []struct {
		name string
		opts []Option
	}{
		{"missing factory", []Option{WithShares(share)}},
		{"nil factory", []Option{WithShares(share), WithAuth(nil)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.opts...)
			if err == nil || !strings.Contains(err.Error(), "authentication factory is required") {
				t.Fatalf("New returned %v; expected authentication rejection", err)
			}
		})
	}
}

// TestNewAcceptsExplicitAuthentication verifies that applications can
// still supply an authentication provider. AlwaysAllowFactory is used
// strictly for this constructor test, never for production deployment.
func TestNewAcceptsExplicitAuthentication(t *testing.T) {
	_, err := New(
		WithShares(vfs.NewDiskShare("share", newMemBackend())),
		WithAuth(auth.AlwaysAllowFactory()),
	)
	if err != nil {
		t.Fatalf("New rejected explicit authentication: %v", err)
	}
}
