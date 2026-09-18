package server

import (
	"testing"

	"github.com/sonroyaalmerol/go-smb-server/smb/transport"
	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

// Share names are case-insensitive: macOS sends them upper-cased.
func TestTreeConnectShareNameIgnoresCase(t *testing.T) {
	for _, path := range []string{`\\server\share`, `\\SERVER\SHARE`, `\\127.0.0.1\Share`} {
		client, srvConn := newPipeConns()
		stop := serveOn(newTestServer(newMemBackend()), srvConn)

		fc := transport.NewFramedConn(client)
		negotiate(t, fc)
		sessID := sessionSetup(t, fc)
		mustWrite(t, fc, buildTreeConnect(sessID, path))
		if rh, _ := readReply(t, fc); rh.Status != wire.StatusSuccess {
			t.Errorf("tree connect %s: status %#x, want success", path, rh.Status)
		}

		stop()
		_ = client.Close()
	}

	client, srvConn := newPipeConns()
	defer func() { _ = client.Close() }()
	defer serveOn(newTestServer(newMemBackend()), srvConn)()
	fc := transport.NewFramedConn(client)
	negotiate(t, fc)
	sessID := sessionSetup(t, fc)
	mustWrite(t, fc, buildTreeConnect(sessID, `\\server\other`))
	if rh, _ := readReply(t, fc); rh.Status != wire.StatusBadNetworkName {
		t.Errorf("tree connect to a missing share: status %#x, want STATUS_BAD_NETWORK_NAME", rh.Status)
	}
}
