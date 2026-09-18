package server

import (
	"encoding/binary"
	"testing"

	"github.com/sonroyaalmerol/go-smb-server/smb/transport"
	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

// The server grants what a client asks for rather than its whole maximum at
// once: macOS does not count credits granted in the NEGOTIATE response, so a
// server that front-loads them there leaves it short of credits afterwards.
func TestCreditsFollowTheClientsRequest(t *testing.T) {
	srv := newTestServer(newMemBackend())
	srv.maxCredits = 512

	client, srvConn := newPipeConns()
	defer func() { _ = client.Close() }()
	defer serveOn(srv, srvConn)()
	fc := transport.NewFramedConn(client)

	send := func(msg []byte, request uint16) uint16 {
		t.Helper()
		// CreditRequest sits at offset 14 of the header.
		msg[14], msg[15] = byte(request), byte(request>>8)
		mustWrite(t, fc, msg)
		rh, _ := readReply(t, fc)
		return rh.Credit
	}

	negHdr := wire.NewHeader(wire.CmdNegotiate)
	negBody := make([]byte, 38)
	binary.LittleEndian.PutUint16(negBody[0:2], 36)
	binary.LittleEndian.PutUint16(negBody[2:4], 1)
	binary.LittleEndian.PutUint16(negBody[36:38], wire.DialectSMB302)
	neg := append(negHdr.Append(nil), negBody...)
	if got := send(neg, 0); got != 1 {
		t.Errorf("NEGOTIATE asking for 0 credits was granted %d, want 1", got)
	}
	sess := buildSessionSetup([]byte{0x60, 0x04, 0xbe, 0xef})
	if got := send(sess, 256); got != 256 {
		t.Errorf("SESSION_SETUP asking for 256 credits was granted %d, want 256", got)
	}
	// 1 + 256 granted, 2 used: only 257 more fit under the maximum of 512.
	echo := wire.NewHeader(wire.CmdEcho)
	echo.MessageId = 2
	echoMsg := append(echo.Append(nil), 4, 0, 0, 0)
	if got := send(echoMsg, 400); got != 257 {
		t.Errorf("request for 400 credits near the maximum was granted %d, want 257", got)
	}
}
