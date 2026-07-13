package wire

import (
	"bytes"
	"testing"
	"time"
)

func TestHeaderRoundTrip(t *testing.T) {
	in := NewHeader(CmdNegotiate)
	in.CreditCharge = 2
	in.Status = StatusSuccess
	in.Credit = 7
	in.Flags = FlagServerToRedir
	in.MessageId = 42
	in.TreeId = 0xFFFFFFFF
	in.SessionId = 0x1234

	b := in.Append(nil)
	if len(b) != HeaderSize {
		t.Fatalf("header size = %d, want %d", len(b), HeaderSize)
	}
	if [4]byte{b[0], b[1], b[2], b[3]} != SMB2ProtocolId {
		t.Fatalf("bad protocol id: % x", b[:4])
	}

	var out Header
	if err := out.Parse(b); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if out.Command != in.Command || out.MessageId != in.MessageId ||
		out.SessionId != in.SessionId || out.TreeId != in.TreeId ||
		out.Flags != in.Flags || out.Credit != in.Credit {
		t.Fatalf("roundtrip mismatch:\nin  = %+v\nout = %+v", in, out)
	}
	if !out.IsResponse() {
		t.Fatal("IsResponse should be true")
	}
}

func TestHeaderBadProtocolId(t *testing.T) {
	b := make([]byte, HeaderSize)
	b[0], b[1], b[2], b[3] = 0xFF, 'S', 'M', 'B'
	var h Header
	if err := h.Parse(b); err == nil {
		t.Fatal("expected error for bad protocol id")
	}
}

func TestNegotiateRequestParse(t *testing.T) {
	body := make([]byte, 42)
	put16(body[0:2], 36)
	put16(body[2:4], 3)
	put16(body[4:6], SigningEnabled)
	put16(body[36:38], DialectSMB202)
	put16(body[38:40], DialectSMB21)
	put16(body[40:42], DialectSMB302)

	var req NegotiateRequest
	if err := req.Parse(body); err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []uint16{DialectSMB202, DialectSMB21, DialectSMB302}
	if len(req.Dialects) != len(want) {
		t.Fatalf("dialects = %v, want %v", req.Dialects, want)
	}
	for i, d := range want {
		if req.Dialects[i] != d {
			t.Fatalf("dialect[%d] = %x, want %x", i, req.Dialects[i], d)
		}
	}
}

func TestNegotiateResponseRoundTrip(t *testing.T) {
	resp := NegotiateResponse{
		SecurityMode:    SigningEnabled,
		DialectRevision: DialectSMB302,
		Capabilities:    CapLargeMTU,
		MaxTransactSize: 65536,
		MaxReadSize:     1048576,
		MaxWriteSize:    1048576,
		SecurityBuffer:  []byte{0x60, 0x06, 0xde, 0xad, 0xbe, 0xef},
	}
	out := resp.Append(nil)
	secBufOff := int(uint16(out[56]) | uint16(out[57])<<8)
	secBufLen := int(uint16(out[58]) | uint16(out[59])<<8)
	if secBufOff != HeaderSize+64 {
		t.Fatalf("SecurityBufferOffset = %d, want %d", secBufOff, HeaderSize+64)
	}
	if secBufLen != len(resp.SecurityBuffer) {
		t.Fatalf("SecurityBufferLength = %d, want %d", secBufLen, len(resp.SecurityBuffer))
	}
	start := secBufOff - HeaderSize
	if !bytes.Equal(out[start:start+secBufLen], resp.SecurityBuffer) {
		t.Fatal("security buffer bytes mismatch")
	}
}

func TestFiletimeRoundTrip(t *testing.T) {
	cases := []time.Time{
		time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
		time.Date(2035, 6, 7, 8, 9, 10, 500, time.UTC),
		time.Unix(0, 0).UTC(),
	}
	for _, tc := range cases {
		ft := TimeToFiletime(tc)
		got := FiletimeToTime(ft)
		if !got.Equal(tc) {
			t.Fatalf("roundtrip %v: ft=%d got=%v", tc, ft, got)
		}
	}
	if TimeToFiletime(time.Time{}) != 0 {
		t.Fatal("zero time should map to 0")
	}
	if !FiletimeToTime(0).IsZero() {
		t.Fatal("0 should map to zero time")
	}
}

func TestAppendFileDirInfo(t *testing.T) {
	fi := FileInfo{Name: "hello.txt", EndOfFile: 100, FileAttributes: 0x20}
	out, s0 := AppendFileDirInfo(nil, fi)
	out, s1 := AppendFileDirInfo(out, FileInfo{Name: "b.txt"})
	SetNextEntryOffset(out, s0, s1)

	next0 := int(out[s0]) | int(out[s0+1])<<8 | int(out[s0+2])<<16 | int(out[s0+3])<<24
	if next0 != s1-s0 {
		t.Fatalf("NextEntryOffset[0] = %d, want %d", next0, s1-s0)
	}
	nameLen0 := int(out[s0+60]) | int(out[s0+61])<<8
	name0 := UTF16FromBytes(out[s0+64 : s0+64+nameLen0])
	if name0 != "hello.txt" {
		t.Fatalf("name0 = %q, want hello.txt", name0)
	}
	next1 := int(out[s1]) | int(out[s1+1])<<8 | int(out[s1+2])<<16 | int(out[s1+3])<<24
	if next1 != 0 {
		t.Fatalf("NextEntryOffset[1] = %d, want 0", next1)
	}
}

func TestUTF16RoundTrip(t *testing.T) {
	for _, s := range []string{"", "a", "hello.txt", "日本語", "\\srv\\share"} {
		b := UTF16ToBytes(s)
		if got := UTF16FromBytes(b); got != s {
			t.Fatalf("roundtrip %q -> %q", s, got)
		}
	}
}

func TestCreateRequestParse(t *testing.T) {
	name := UTF16ToBytes("dir/file.txt")
	msg := make([]byte, createBody+57+len(name))
	put16(msg[createBody:createBody+2], 57)
	put32(msg[createBody+36:createBody+40], FileOpenIf)
	nameOff := createBody + 56
	nameOff = (nameOff + 7) &^ 7
	put16(msg[createBody+44:createBody+46], uint16(nameOff))
	put16(msg[createBody+46:createBody+48], uint16(len(name)))
	copy(msg[nameOff:], name)

	var req CreateRequest
	if err := req.Parse(msg); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if req.CreateDisposition != FileOpenIf {
		t.Fatalf("disposition = %x", req.CreateDisposition)
	}
	if UTF16FromBytes(req.Name) != "dir/file.txt" {
		t.Fatalf("name = %q", UTF16FromBytes(req.Name))
	}
}
