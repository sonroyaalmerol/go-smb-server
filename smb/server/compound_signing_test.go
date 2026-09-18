package server

import (
	"encoding/binary"
	"testing"

	"github.com/sonroyaalmerol/go-smb-server/smb/signing"
	"github.com/sonroyaalmerol/go-smb-server/smb/transport"
	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

// Every response in a compound reply carries a signature that covers its
// padding and NextCommand. macOS verifies each one and drops a response whose
// signature fails, which left its SMB client waiting on replies it had
// already been sent.
func TestCompoundResponsesAreEachSigned(t *testing.T) {
	kt := newKerbTestKeytab(t)
	token, sessionKey := buildKerbToken(t, kt)

	client, srvConn := newPipeConns()
	defer func() { _ = client.Close() }()
	defer serveOn(newKerbTestServer(t, newMemBackend(), kt), srvConn)()
	fc := transport.NewFramedConn(client)

	negBody := make([]byte, 38)
	binary.LittleEndian.PutUint16(negBody[0:2], 36)
	binary.LittleEndian.PutUint16(negBody[2:4], 1)
	binary.LittleEndian.PutUint16(negBody[36:38], wire.DialectSMB302)
	hdr := wire.NewHeader(wire.CmdNegotiate)
	hdr.Credit = 1
	mustWrite(t, fc, append(hdr.Append(nil), negBody...))
	if rh, _ := readReply(t, fc); rh.Status != wire.StatusSuccess {
		t.Fatalf("negotiate: %#x", rh.Status)
	}
	mustWrite(t, fc, buildSessionSetup(token))
	rh, _ := readReply(t, fc)
	if rh.Status != wire.StatusSuccess {
		t.Fatalf("session_setup: %#x", rh.Status)
	}
	sessID := rh.SessionId
	key := signing.DeriveSigningKey(sessionKey)
	mustWrite(t, fc, signedTreeConnect(sessID, 2, `\\server\share`, key))
	rh, _ = readReply(t, fc)
	if rh.Status != wire.StatusSuccess {
		t.Fatalf("tree_connect: %#x", rh.Status)
	}
	treeID := rh.TreeId

	// CREATE + QUERY_INFO + CLOSE on the created handle, as macOS sends to
	// read a file's attributes.
	var chained [16]byte
	for i := range chained {
		chained[i] = 0xFF
	}
	parts := [][]byte{
		buildCreate(sessID, treeID, "attrs.txt", wire.FileOpenIf),
		buildQueryInfo(sessID, treeID, chained, wire.FileStandardInfoClass),
		buildClose(sessID, treeID, chained),
	}
	var compound []byte
	for i, p := range parts {
		binary.LittleEndian.PutUint64(p[24:32], uint64(10+i))
		if i > 0 {
			flags := binary.LittleEndian.Uint32(p[16:20]) | wire.FlagRelatedOps
			binary.LittleEndian.PutUint32(p[16:20], flags)
		}
		if i < len(parts)-1 {
			for len(p)%8 != 0 {
				p = append(p, 0)
			}
			binary.LittleEndian.PutUint32(p[20:24], uint32(len(p)))
		}
		compound = append(compound, p...)
	}
	mustWrite(t, fc, compound)

	reply, err := fc.ReadMessage()
	if err != nil {
		t.Fatalf("read compound reply: %v", err)
	}
	verifier, err := signing.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for off := 0; ; count++ {
		var h wire.Header
		if err := h.Parse(reply[off:]); err != nil {
			t.Fatalf("response %d: %v", count, err)
		}
		end := len(reply)
		if h.NextCommand != 0 {
			end = off + int(h.NextCommand)
		}
		if h.Status != wire.StatusSuccess {
			t.Errorf("response %d (command %d): status %#x", count, h.Command, h.Status)
		}
		if h.Flags&wire.FlagSigned == 0 {
			t.Errorf("response %d (command %d) is not signed", count, h.Command)
		} else if ok, err := verifier.Verify(append([]byte(nil), reply[off:end]...)); err != nil || !ok {
			t.Errorf("response %d (command %d): signature does not verify", count, h.Command)
		}
		if h.NextCommand == 0 {
			break
		}
		off = end
	}
	if count+1 != len(parts) {
		t.Fatalf("got %d responses, want %d", count+1, len(parts))
	}
}
