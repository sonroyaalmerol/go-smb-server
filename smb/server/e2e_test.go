package server

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/sonroyaalmerol/go-smb-server/smb/auth"
	"github.com/sonroyaalmerol/go-smb-server/smb/transport"
	"github.com/sonroyaalmerol/go-smb-server/smb/vfs"
	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

func newPipeConns() (client, server net.Conn) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	serverCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(serverCh)
			return
		}
		serverCh <- c
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		panic(err)
	}
	server = <-serverCh
	_ = ln.Close()
	return client, server
}

func serveOn(srv *Server, c net.Conn) context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())
	go srv.serveConn(ctx, c)
	return func() {
		cancel()
		_ = c.Close()
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestServer(backend vfs.Backend) *Server {
	return &Server{
		shareByName: map[string]vfs.Share{"share": vfs.NewDiskShare("share", backend)},
		shares:      []vfs.Share{vfs.NewDiskShare("share", backend)},
		authFactory: auth.AlwaysAllowFactory(),
		dialect:     wire.DialectSMB302,
		maxTransact: 65536,
		maxRead:     1 << 20,
		maxWrite:    1 << 20,
		log:         discardLogger(),
	}
}

func readReply(t *testing.T, r io.Reader) (wire.Header, []byte) {
	t.Helper()
	var buf []byte
	msg, err := transport.ReadFrame(r, &buf)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	var h wire.Header
	if err := h.Parse(msg); err != nil {
		t.Fatalf("parse header: %v", err)
	}
	return h, msg
}

func mustWrite(t *testing.T, fc *transport.FramedConn, msg []byte) {
	t.Helper()
	if err := fc.WriteMessage(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestEndToEnd_Negotiate(t *testing.T) {
	client, srvConn := newPipeConns()
	defer client.Close()
	srv := newTestServer(newMemBackend())
	cancel := serveOn(srv, srvConn)
	defer cancel()

	fc := transport.NewFramedConn(client)

	hdr := wire.NewHeader(wire.CmdNegotiate)
	hdr.Credit = 1
	hdr.MessageId = 0
	body := make([]byte, 38)
	binary.LittleEndian.PutUint16(body[0:2], 36)
	binary.LittleEndian.PutUint16(body[2:4], 1)
	binary.LittleEndian.PutUint16(body[36:38], wire.DialectSMB302)
	msg := hdr.Append(nil)
	msg = append(msg, body...)
	mustWrite(t, fc, msg)

	rh, _ := readReply(t, fc.Underlying())
	if rh.Command != wire.CmdNegotiate {
		t.Fatalf("command = %x, want negotiate", rh.Command)
	}
	if rh.Status != wire.StatusSuccess {
		t.Fatalf("negotiate status = %x", rh.Status)
	}
}

func TestEndToEnd_FullConversation(t *testing.T) {
	backend := newMemBackend()
	client, srvConn := newPipeConns()
	defer client.Close()
	srv := newTestServer(backend)
	cancel := serveOn(srv, srvConn)
	defer cancel()

	fc := transport.NewFramedConn(client)

	negBody := make([]byte, 38)
	binary.LittleEndian.PutUint16(negBody[0:2], 36)
	binary.LittleEndian.PutUint16(negBody[2:4], 1)
	binary.LittleEndian.PutUint16(negBody[36:38], wire.DialectSMB302)
	hdr := wire.NewHeader(wire.CmdNegotiate)
	hdr.MessageId = 0
	hdr.Credit = 1
	msg := hdr.Append(nil)
	msg = append(msg, negBody...)
	mustWrite(t, fc, msg)
	rh, _ := readReply(t, fc.Underlying())
	if rh.Status != wire.StatusSuccess {
		t.Fatalf("negotiate: %x", rh.Status)
	}

	mustWrite(t, fc, buildSessionSetup([]byte{0x60, 0x04, 0xbe, 0xef}))
	rh, _ = readReply(t, fc.Underlying())
	if rh.Status != wire.StatusSuccess {
		t.Fatalf("session_setup: %x", rh.Status)
	}
	sessID := rh.SessionId

	mustWrite(t, fc, buildTreeConnect(sessID, `\\server\share`))
	rh, resp := readReply(t, fc.Underlying())
	if rh.Status != wire.StatusSuccess {
		t.Fatalf("tree_connect: %x", rh.Status)
	}
	if resp[64+2] != wire.ShareTypeDisk {
		t.Fatalf("share type = %x, want disk", resp[64+2])
	}
	treeID := rh.TreeId

	mustWrite(t, fc, buildCreate(sessID, treeID, "test.txt", wire.FileOpenIf))
	rh, resp = readReply(t, fc.Underlying())
	if rh.Status != wire.StatusSuccess {
		t.Fatalf("create: %x", rh.Status)
	}
	var fid [16]byte
	copy(fid[:], resp[64+64:64+80])

	mustWrite(t, fc, buildWrite(sessID, treeID, fid, 0, []byte("hello")))
	rh, _ = readReply(t, fc.Underlying())
	if rh.Status != wire.StatusSuccess {
		t.Fatalf("write: %x", rh.Status)
	}

	mustWrite(t, fc, buildRead(sessID, treeID, fid, 0, 5))
	rh, resp = readReply(t, fc.Underlying())
	if rh.Status != wire.StatusSuccess {
		t.Fatalf("read: %x", rh.Status)
	}
	if string(resp[64+16:]) != "hello" {
		t.Fatalf("read data = %q", string(resp[64+16:]))
	}

	mustWrite(t, fc, buildClose(sessID, treeID, fid))
	rh, _ = readReply(t, fc.Underlying())
	if rh.Status != wire.StatusSuccess {
		t.Fatalf("close: %x", rh.Status)
	}
}

func buildSessionSetup(token []byte) []byte {
	hdr := wire.NewHeader(wire.CmdSessionSetup)
	hdr.MessageId = 1
	hdr.Credit = 1
	body := make([]byte, 24+len(token))
	binary.LittleEndian.PutUint16(body[0:2], 25)
	binary.LittleEndian.PutUint16(body[8:10], uint16(wire.HeaderSize+24))
	binary.LittleEndian.PutUint16(body[10:12], uint16(len(token)))
	copy(body[24:], token)
	m := hdr.Append(nil)
	return append(m, body...)
}

func buildTreeConnect(sessID uint64, share string) []byte {
	pathBytes := wire.UTF16ToBytes(share)
	hdr := wire.NewHeader(wire.CmdTreeConnect)
	hdr.SessionId = sessID
	hdr.MessageId = 2
	hdr.Credit = 1
	body := make([]byte, 8+len(pathBytes))
	binary.LittleEndian.PutUint16(body[0:2], 9)
	binary.LittleEndian.PutUint16(body[4:6], uint16(wire.HeaderSize+8))
	binary.LittleEndian.PutUint16(body[6:8], uint16(len(pathBytes)))
	copy(body[8:], pathBytes)
	m := hdr.Append(nil)
	return append(m, body...)
}

func buildCreate(sessID uint64, treeID uint32, name string, disposition uint32) []byte {
	nameBytes := wire.UTF16ToBytes(name)
	hdr := wire.NewHeader(wire.CmdCreate)
	hdr.SessionId = sessID
	hdr.TreeId = treeID
	hdr.MessageId = 3
	hdr.Credit = 1
	const fixed = 57
	nameOff := (wire.HeaderSize + fixed + 7) &^ 7
	pad := nameOff - (wire.HeaderSize + fixed)
	body := make([]byte, fixed+pad+len(nameBytes))
	binary.LittleEndian.PutUint16(body[0:2], 57)
	binary.LittleEndian.PutUint32(body[36:40], disposition)
	binary.LittleEndian.PutUint16(body[44:46], uint16(nameOff))
	binary.LittleEndian.PutUint16(body[46:48], uint16(len(nameBytes)))
	copy(body[fixed+pad:], nameBytes)
	m := hdr.Append(nil)
	return append(m, body...)
}

func buildWrite(sessID uint64, treeID uint32, fid [16]byte, offset uint64, data []byte) []byte {
	hdr := wire.NewHeader(wire.CmdWrite)
	hdr.SessionId = sessID
	hdr.TreeId = treeID
	hdr.MessageId = 4
	hdr.Credit = 1
	const fixed = 48
	dataOff := wire.HeaderSize + fixed
	body := make([]byte, fixed+len(data))
	binary.LittleEndian.PutUint16(body[0:2], 49)
	binary.LittleEndian.PutUint16(body[2:4], uint16(dataOff))
	binary.LittleEndian.PutUint32(body[4:8], uint32(len(data)))
	binary.LittleEndian.PutUint64(body[8:16], offset)
	copy(body[16:32], fid[:])
	copy(body[fixed:], data)
	m := hdr.Append(nil)
	return append(m, body...)
}

func buildRead(sessID uint64, treeID uint32, fid [16]byte, offset uint64, length uint32) []byte {
	hdr := wire.NewHeader(wire.CmdRead)
	hdr.SessionId = sessID
	hdr.TreeId = treeID
	hdr.MessageId = 5
	hdr.Credit = 1
	var body [49]byte
	binary.LittleEndian.PutUint16(body[0:2], 49)
	binary.LittleEndian.PutUint32(body[4:8], length)
	binary.LittleEndian.PutUint64(body[8:16], offset)
	copy(body[16:32], fid[:])
	m := hdr.Append(nil)
	return append(m, body[:]...)
}

func buildClose(sessID uint64, treeID uint32, fid [16]byte) []byte {
	hdr := wire.NewHeader(wire.CmdClose)
	hdr.SessionId = sessID
	hdr.TreeId = treeID
	hdr.MessageId = 6
	hdr.Credit = 1
	var body [24]byte
	binary.LittleEndian.PutUint16(body[0:2], 24)
	copy(body[8:24], fid[:])
	m := hdr.Append(nil)
	return append(m, body[:]...)
}

func buildQueryDirectory(sessID uint64, treeID uint32, fid [16]byte, pattern string) []byte {
	patBytes := wire.UTF16ToBytes(pattern)
	hdr := wire.NewHeader(wire.CmdQueryDirectory)
	hdr.SessionId = sessID
	hdr.TreeId = treeID
	hdr.MessageId = 7
	hdr.Credit = 1
	const fixed = 33
	patOff := (wire.HeaderSize + fixed + 7) &^ 7
	pad := patOff - (wire.HeaderSize + fixed)
	body := make([]byte, fixed+pad+len(patBytes))
	binary.LittleEndian.PutUint16(body[0:2], 33)
	body[2] = 0x01
	copy(body[8:24], fid[:])
	binary.LittleEndian.PutUint16(body[24:26], uint16(patOff))
	binary.LittleEndian.PutUint16(body[26:28], uint16(len(patBytes)))
	binary.LittleEndian.PutUint32(body[28:32], 4096)
	copy(body[fixed+pad:], patBytes)
	m := hdr.Append(nil)
	return append(m, body...)
}

func TestEndToEnd_QueryDirectory(t *testing.T) {
	backend := newMemBackend()
	if _, err := backend.Open(context.Background(), vfs.OpenOptions{Path: "a.txt", Disposition: vfs.DispositionCreate}); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Open(context.Background(), vfs.OpenOptions{Path: "b.txt", Disposition: vfs.DispositionCreate}); err != nil {
		t.Fatal(err)
	}

	client, srvConn := newPipeConns()
	defer client.Close()
	defer serveOn(newTestServer(backend), srvConn)()

	fc := transport.NewFramedConn(client)
	negotiate(t, fc)
	sessID := sessionSetup(t, fc)
	treeID := treeConnect(t, fc, sessID)

	createMsg := buildCreate(sessID, treeID, "", wire.FileOpen)
	mustWrite(t, fc, createMsg)
	rh, resp := readReply(t, fc.Underlying())
	if rh.Status != wire.StatusSuccess {
		t.Fatalf("create dir: %x", rh.Status)
	}
	var dirFid [16]byte
	copy(dirFid[:], resp[64+64:64+80])

	mustWrite(t, fc, buildQueryDirectory(sessID, treeID, dirFid, "*"))
	rh, resp = readReply(t, fc.Underlying())
	if rh.Status != wire.StatusSuccess {
		t.Fatalf("query_directory: %x", rh.Status)
	}
	bufLen := binary.LittleEndian.Uint32(resp[64+4 : 64+8])
	names := parseDirInfoNames(resp[64+8 : 64+8+int(bufLen)])
	if len(names) != 2 {
		t.Fatalf("entries = %v, want 2", names)
	}
}

func negotiate(t *testing.T, fc *transport.FramedConn) {
	t.Helper()
	negBody := make([]byte, 38)
	binary.LittleEndian.PutUint16(negBody[0:2], 36)
	binary.LittleEndian.PutUint16(negBody[2:4], 1)
	binary.LittleEndian.PutUint16(negBody[36:38], wire.DialectSMB302)
	hdr := wire.NewHeader(wire.CmdNegotiate)
	hdr.MessageId = 0
	hdr.Credit = 1
	msg := hdr.Append(nil)
	msg = append(msg, negBody...)
	mustWrite(t, fc, msg)
	rh, _ := readReply(t, fc.Underlying())
	if rh.Status != wire.StatusSuccess {
		t.Fatalf("negotiate: %x", rh.Status)
	}
}

func sessionSetup(t *testing.T, fc *transport.FramedConn) uint64 {
	t.Helper()
	mustWrite(t, fc, buildSessionSetup([]byte{0x60, 0x04, 0xbe, 0xef}))
	rh, _ := readReply(t, fc.Underlying())
	if rh.Status != wire.StatusSuccess {
		t.Fatalf("session_setup: %x", rh.Status)
	}
	return rh.SessionId
}

func treeConnect(t *testing.T, fc *transport.FramedConn, sessID uint64) uint32 {
	t.Helper()
	mustWrite(t, fc, buildTreeConnect(sessID, `\\server\share`))
	rh, _ := readReply(t, fc.Underlying())
	if rh.Status != wire.StatusSuccess {
		t.Fatalf("tree_connect: %x", rh.Status)
	}
	return rh.TreeId
}

func parseDirInfoNames(buf []byte) []string {
	var names []string
	off := 0
	for off+64 <= len(buf) {
		next := int(binary.LittleEndian.Uint32(buf[off : off+4]))
		nameLen := int(binary.LittleEndian.Uint32(buf[off+60 : off+64]))
		names = append(names, wire.UTF16FromBytes(buf[off+64:off+64+nameLen]))
		if next == 0 {
			break
		}
		off += next
	}
	return names
}

func TestEndToEnd_QueryInfoAndDeleteOnClose(t *testing.T) {
	backend := newMemBackend()
	client, srvConn := newPipeConns()
	defer client.Close()
	defer serveOn(newTestServer(backend), srvConn)()

	fc := transport.NewFramedConn(client)
	negotiate(t, fc)
	sessID := sessionSetup(t, fc)
	treeID := treeConnect(t, fc, sessID)

	// CREATE a file
	mustWrite(t, fc, buildCreate(sessID, treeID, "qinfo.txt", wire.FileOpenIf))
	rh, resp := readReply(t, fc.Underlying())
	if rh.Status != wire.StatusSuccess {
		t.Fatalf("create: %x", rh.Status)
	}
	var fid [16]byte
	copy(fid[:], resp[64+64:64+80])

	// QUERY_INFO FileBasicInformation
	mustWrite(t, fc, buildQueryInfo(sessID, treeID, fid, wire.FileBasicInfoClass))
	rh, qResp := readReply(t, fc.Underlying())
	if rh.Status != wire.StatusSuccess {
		t.Fatalf("query_info: %x", rh.Status)
	}
	bufLen := int(binary.LittleEndian.Uint32(qResp[64+4 : 64+8]))
	if bufLen < 40 {
		t.Fatalf("FileBasicInformation len = %d, want >= 40", bufLen)
	}

	// SET_INFO FileDispositionInformation = 1 (delete on close)
	mustWrite(t, fc, buildSetInfo(sessID, treeID, fid, wire.FileDispositionInformation, []byte{1}))
	rh, _ = readReply(t, fc.Underlying())
	if rh.Status != wire.StatusSuccess {
		t.Fatalf("set_info: %x", rh.Status)
	}

	// CLOSE should delete the file
	mustWrite(t, fc, buildClose(sessID, treeID, fid))
	rh, _ = readReply(t, fc.Underlying())
	if rh.Status != wire.StatusSuccess {
		t.Fatalf("close: %x", rh.Status)
	}

	// Re-open should now fail (file gone).
	mustWrite(t, fc, buildCreate(sessID, treeID, "qinfo.txt", wire.FileOpen))
	rh, _ = readReply(t, fc.Underlying())
	if rh.Status == wire.StatusSuccess {
		t.Fatal("expected file to be deleted")
	}
}

func buildQueryInfo(sessID uint64, treeID uint32, fid [16]byte, class uint8) []byte {
	hdr := wire.NewHeader(wire.CmdQueryInfo)
	hdr.SessionId = sessID
	hdr.TreeId = treeID
	hdr.MessageId = 20
	hdr.Credit = 1
	var body [41]byte
	binary.LittleEndian.PutUint16(body[0:2], 41)
	body[2] = wire.InfoFile
	body[3] = class
	binary.LittleEndian.PutUint32(body[4:8], 4096)
	copy(body[24:40], fid[:])
	m := hdr.Append(nil)
	return append(m, body[:]...)
}

func buildSetInfo(sessID uint64, treeID uint32, fid [16]byte, class uint8, buf []byte) []byte {
	hdr := wire.NewHeader(wire.CmdSetInfo)
	hdr.SessionId = sessID
	hdr.TreeId = treeID
	hdr.MessageId = 21
	hdr.Credit = 1
	const fixed = 32
	bufOff := wire.HeaderSize + fixed
	body := make([]byte, fixed+len(buf))
	binary.LittleEndian.PutUint16(body[0:2], 33)
	body[2] = wire.InfoFile
	body[3] = class
	binary.LittleEndian.PutUint32(body[4:8], uint32(len(buf)))
	binary.LittleEndian.PutUint16(body[8:10], uint16(bufOff))
	copy(body[16:32], fid[:])
	copy(body[fixed:], buf)
	m := hdr.Append(nil)
	return append(m, body...)
}
