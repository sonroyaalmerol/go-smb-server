package server

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/sonroyaalmerol/go-smb-server/smb/transport"
	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

// A request whose bytes arrive slowly must still be read whole. A large
// WRITE on a busy network can take longer than the connection's 200ms read
// poll to arrive; a read that gave up partway through a frame read the rest
// of it as a new header, and the connection dropped.
func TestRequestArrivingInPiecesIsReadWhole(t *testing.T) {
	for _, tc := range []struct {
		name  string
		split int // bytes of the framed message sent before the stall
	}{
		{"stall inside the frame header", 2},
		{"stall inside the message", 4 + 30},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, srvConn := newPipeConns()
			defer func() { _ = client.Close() }()
			cancel := serveOn(newTestServer(newMemBackend()), srvConn)
			defer cancel()

			hdr := wire.NewHeader(wire.CmdNegotiate)
			hdr.Credit = 1
			body := make([]byte, 38)
			binary.LittleEndian.PutUint16(body[0:2], 36)
			binary.LittleEndian.PutUint16(body[2:4], 1)
			binary.LittleEndian.PutUint16(body[36:38], wire.DialectSMB302)
			msg := append(hdr.Append(nil), body...)

			framed := make([]byte, 4, 4+len(msg))
			framed[1] = byte(len(msg) >> 16)
			framed[2] = byte(len(msg) >> 8)
			framed[3] = byte(len(msg))
			framed = append(framed, msg...)

			if _, err := client.Write(framed[:tc.split]); err != nil {
				t.Fatalf("write first part: %v", err)
			}
			time.Sleep(350 * time.Millisecond)
			if _, err := client.Write(framed[tc.split:]); err != nil {
				t.Fatalf("write the rest: %v", err)
			}

			_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
			reply, err := transport.NewFramedConn(client).ReadMessage()
			if err != nil {
				t.Fatalf("no reply to a request that arrived in two pieces: %v", err)
			}
			var h wire.Header
			if err := h.Parse(reply); err != nil {
				t.Fatalf("parse reply: %v", err)
			}
			if h.Command != wire.CmdNegotiate || h.Status != wire.StatusSuccess {
				t.Fatalf("reply command %x status %x, want a successful negotiate", h.Command, h.Status)
			}
		})
	}
}
