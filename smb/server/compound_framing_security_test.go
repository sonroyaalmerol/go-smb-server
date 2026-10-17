package server

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

// TestCompoundFramingSecurity checks that untrusted NextCommand
// offsets cannot cause a malformed compound request to be dispatched.
// See MS-SMB2 compound request framing requirements.
func TestCompoundFramingSecurity(t *testing.T) {
	first := wire.NewHeader(wire.CmdEcho)
	second := wire.NewHeader(wire.CmdEcho)

	single := first.Append(nil)

	first.NextCommand = wire.HeaderSize
	compound := second.Append(first.Append(nil))

	badSecond := append([]byte(nil), compound...)
	badSecond[wire.HeaderSize] = 0xFF

	unaligned := append([]byte(nil), compound...)
	unaligned[20] = 65

	truncatedNext := append([]byte(nil), compound...)
	truncatedNext[20] = 120

	tests := []struct {
		name  string
		msg   []byte
		valid bool
	}{
		{"single", single, true},
		{"two_commands", compound, true},
		{"short_header", single[:wire.HeaderSize-1], false},
		{"unaligned_offset", unaligned, false},
		{"insufficient_next_header", truncatedNext, false},
		{"bad_second_header", badSecond, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCompoundRequest(tt.msg)
			if (err == nil) != tt.valid {
				t.Fatalf("valid=%v, validation error=%v", tt.valid, err)
			}

			if tt.valid {
				return
			}

			c := &conn{
				log: slog.New(slog.NewTextHandler(io.Discard, nil)),
				out: []byte{1, 2, 3},
			}
			c.handleMessage(context.Background(),
				append([]byte(nil), tt.msg...))
			if len(c.out) != 0 {
				t.Fatal("SECURITY FAILURE: malformed request retained response bytes")
			}
		})
	}
}
