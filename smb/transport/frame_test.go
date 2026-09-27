package transport

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

// A reader that polls with short read deadlines sees a large frame arrive
// over several polls. Each ReadMessage that times out must resume the frame
// rather than read its remainder as a new header.
func TestReadMessageResumesAfterDeadline(t *testing.T) {
	for _, tc := range []struct {
		name   string
		splits []int // offsets into the framed bytes where the writer pauses
	}{
		{"pause inside the header", []int{2}},
		{"pause after the header", []int{HeaderLen}},
		{"pause inside the body", []int{HeaderLen + 1000}},
		{"several pauses", []int{1, 3, HeaderLen + 10, HeaderLen + 40000}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			accepted := make(chan net.Conn, 1)
			go func() {
				c, _ := ln.Accept()
				accepted <- c
			}()
			writer, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			reader := <-accepted
			defer reader.Close()

			first := bytes.Repeat([]byte("slow frame "), 6000)
			second := []byte("the frame after it")
			var wire bytes.Buffer
			for _, p := range [][]byte{first, second} {
				var hdr [HeaderLen]byte
				writeUint24(hdr[1:], uint32(len(p)))
				wire.Write(hdr[:])
				wire.Write(p)
			}
			framed := wire.Bytes()

			go func() {
				at := 0
				for _, split := range tc.splits {
					_, _ = writer.Write(framed[at:split])
					at = split
					time.Sleep(120 * time.Millisecond)
				}
				_, _ = writer.Write(framed[at:])
			}()

			fc := NewFramedConn(reader)
			read := func() []byte {
				t.Helper()
				deadline := time.Now().Add(5 * time.Second)
				for time.Now().Before(deadline) {
					_ = reader.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
					msg, err := fc.ReadMessage()
					var ne net.Error
					if errors.As(err, &ne) && ne.Timeout() {
						continue
					}
					if err != nil {
						t.Fatalf("ReadMessage: %v", err)
					}
					return append([]byte(nil), msg...)
				}
				t.Fatal("no frame within 5s")
				return nil
			}
			if got := read(); !bytes.Equal(got, first) {
				t.Fatalf("first frame: got %d bytes, want %d", len(got), len(first))
			}
			if got := read(); !bytes.Equal(got, second) {
				t.Fatalf("second frame = %q, want %q", got, second)
			}
		})
	}
}
