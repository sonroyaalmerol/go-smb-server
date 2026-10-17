package server

import (
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/sonroyaalmerol/go-smb-server/smb/transport"
	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

func TestResponseSecurity_EncryptionFailureMustNotPermitPlaintext(t *testing.T) {
	const sessionID uint64 = 42

	s := &session{
		authenticated:  true,
		requireEncrypt: true,
		encryptionKey:  []byte{1}, // Deliberately invalid AES key.
	}

	c := &conn{
		sessions: map[uint64]*session{sessionID: s},
		log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	hdr := wire.NewHeader(wire.CmdTreeConnect)
	hdr.SessionId = sessionID
	plaintext := hdr.Append(nil)

	sealed, err := c.maybeSealResponse(plaintext)
	if err == nil {
		t.Fatal("SECURITY FAILURE: invalid encryption key was accepted")
	}
	if len(sealed) != 0 {
		t.Fatal("SECURITY FAILURE: encryption failure returned sendable bytes")
	}
}

func TestResponseSecurity_AsyncWriterMustEncrypt(t *testing.T) {
	const sessionID uint64 = 42

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	c := &conn{
		fc: transport.NewFramedConn(server),
		sessions: map[uint64]*session{
			sessionID: {
				authenticated:  true,
				requireEncrypt: true,
				encryptionKey:  []byte("0123456789abcdef"),
			},
		},
		asyncResp: make(chan []byte, 1),
		log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	hdr := wire.NewHeader(wire.CmdChangeNotify)
	hdr.SessionId = sessionID
	hdr.Flags = wire.FlagServerToRedir | wire.FlagAsyncCommand

	c.asyncResp <- hdr.Append(nil)

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.drainAsync()
	}()

	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}

	payload, err := transport.NewFramedConn(client).ReadMessage()
	if err != nil {
		t.Fatalf("read async response: %v", err)
	}

	if len(payload) < 4 ||
		payload[0] != 0xFD ||
		payload[1] != 'S' ||
		payload[2] != 'M' ||
		payload[3] != 'B' {
		t.Fatal("SECURITY FAILURE: asynchronous response transmitted without SMB encryption")
	}

	<-done
}
