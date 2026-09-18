package server

import (
	"encoding/binary"
	"log/slog"
	"testing"

	"github.com/sonroyaalmerol/go-smb-server/smb/vfs"
	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

// smb1Negotiate builds the SMB1 multi-protocol negotiate Windows sends first.
func smb1Negotiate() []byte {
	msg := []byte{0xFF, 'S', 'M', 'B', 0x72}
	msg = append(msg, make([]byte, 27)...)
	dialects := []string{"NT LM 0.12", "SMB 2.002", "SMB 2.???"}
	var body []byte
	for _, dialect := range dialects {
		body = append(body, 0x02)
		body = append(body, dialect...)
		body = append(body, 0x00)
	}
	msg = append(msg, 0x00)
	msg = binary.LittleEndian.AppendUint16(msg, uint16(len(body)))
	return append(msg, body...)
}

func TestSMB1NegotiateAnsweredWithWildcardDialect(t *testing.T) {
	msg := smb1Negotiate()
	if !isSMB1Negotiate(msg) {
		t.Fatal("Windows' SMB1 negotiate was not recognized")
	}
	if isSMB1Negotiate(append([]byte{0xFE, 'S', 'M', 'B'}, make([]byte, 60)...)) {
		t.Fatal("an SMB2 header was mistaken for an SMB1 negotiate")
	}

	srv, err := New(WithAddr("127.0.0.1:0"), WithShares(vfs.NewDiskShare("share", newMemBackend())))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	c := &conn{srv: srv, log: slog.New(slog.DiscardHandler)}
	c.replyWildcardNegotiate()

	if len(c.out) < wire.HeaderSize+6 {
		t.Fatalf("response is %d bytes, too short for a negotiate response", len(c.out))
	}
	var hdr wire.Header
	if err := hdr.Parse(c.out); err != nil {
		t.Fatalf("response header does not parse: %v", err)
	}
	if hdr.Command != wire.CmdNegotiate {
		t.Fatalf("response command = %d, want negotiate", hdr.Command)
	}
	if hdr.Flags&wire.FlagServerToRedir == 0 {
		t.Fatal("response is not marked as a server response")
	}
	body := c.out[wire.HeaderSize:]
	if dialect := binary.LittleEndian.Uint16(body[4:6]); dialect != wire.DialectWildcard {
		t.Fatalf("dialect = %#04x, want the wildcard %#04x", dialect, wire.DialectWildcard)
	}
}

// Related compound commands inherit the previous command's FileId, which the
// server splices into the request at a per-command offset.
func TestFileIdOffsetsMatchRequestLayouts(t *testing.T) {
	// Offsets of the FileId field within each request body (MS-SMB2 2.2).
	tests := []struct {
		command uint16
		body    int
	}{
		{wire.CmdClose, 8},
		{wire.CmdFlush, 8},
		{wire.CmdQueryDirectory, 8},
		{wire.CmdLock, 8},
		{wire.CmdIoctl, 8},
		{wire.CmdRead, 16},
		{wire.CmdWrite, 16},
		{wire.CmdSetInfo, 16},
		{wire.CmdQueryInfo, 24},
	}
	for _, tt := range tests {
		if got := fileIdOffset(tt.command); got != 64+tt.body {
			t.Errorf("fileIdOffset(command %d) = %d, want %d", tt.command, got, 64+tt.body)
		}
	}
	if got := fileIdOffset(wire.CmdNegotiate); got != -1 {
		t.Errorf("fileIdOffset(negotiate) = %d, want -1", got)
	}
}
