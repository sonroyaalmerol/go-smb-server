package server

import (
	"context"
	"testing"

	"github.com/sonroyaalmerol/go-smb-server/smb/transport"
	"github.com/sonroyaalmerol/go-smb-server/smb/vfs"
	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

// A listing that matches nothing answers STATUS_NO_SUCH_FILE; one that has
// returned every match answers STATUS_NO_MORE_FILES. macOS looks up single
// names with a pattern and tells a missing name by the first status.
func TestQueryDirectoryNoMatchVersusExhausted(t *testing.T) {
	backend := newMemBackend()
	if _, err := backend.Open(context.Background(), vfs.OpenOptions{Path: "a.txt", Disposition: vfs.DispositionCreate}); err != nil {
		t.Fatal(err)
	}

	client, srvConn := newPipeConns()
	defer func() { _ = client.Close() }()
	defer serveOn(newTestServer(backend), srvConn)()

	fc := transport.NewFramedConn(client)
	negotiate(t, fc)
	sessID := sessionSetup(t, fc)
	treeID := treeConnect(t, fc, sessID)

	openDir := func() [16]byte {
		t.Helper()
		mustWrite(t, fc, buildCreate(sessID, treeID, "", wire.FileOpen))
		rh, resp := readReply(t, fc)
		if rh.Status != wire.StatusSuccess {
			t.Fatalf("create dir: %#x", rh.Status)
		}
		var fid [16]byte
		copy(fid[:], resp[64+64:64+80])
		return fid
	}
	query := func(fid [16]byte, pattern string) uint32 {
		t.Helper()
		mustWrite(t, fc, buildQueryDirectory(sessID, treeID, fid, pattern))
		rh, _ := readReply(t, fc)
		return rh.Status
	}

	missing := openDir()
	if got := query(missing, "missing.txt"); got != wire.StatusNoSuchFile {
		t.Errorf("first query matching nothing: status %#x, want STATUS_NO_SUCH_FILE", got)
	}

	listed := openDir()
	if got := query(listed, "a.txt"); got != wire.StatusSuccess {
		t.Fatalf("query for an existing name: status %#x, want success", got)
	}
	if got := query(listed, "a.txt"); got != wire.StatusNoMoreFiles {
		t.Errorf("query after every match was returned: status %#x, want STATUS_NO_MORE_FILES", got)
	}
}
