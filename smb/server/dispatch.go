package server

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"

	"github.com/sonroyaalmerol/go-smb-server/smb/auth"
	"github.com/sonroyaalmerol/go-smb-server/smb/encryption"
	"github.com/sonroyaalmerol/go-smb-server/smb/ntlmssp"
	"github.com/sonroyaalmerol/go-smb-server/smb/signing"
	"github.com/sonroyaalmerol/go-smb-server/smb/vfs"
	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

func (c *request) dispatch(ctx context.Context, msg []byte, hdr *wire.Header, lastFileId *[16]byte, related bool) uint32 {
	var sess *session
	var tr *tree
	if requiresSession(hdr.Command) {
		sess = c.getSession(hdr.SessionId)
		if sess == nil || !sess.authenticated {
			if hdr.Command == wire.CmdSessionSetup {
			} else {
				return c.errBody(wire.StatusUserSessionDeleted)
			}
		}
		if sess != nil {
			tr = sess.getTree(hdr.TreeId)
			if requiresTree(hdr.Command) && tr == nil {
				return c.errBody(wire.StatusNetworkNameDeleted)
			}
		}
	}

	switch hdr.Command {
	case wire.CmdNegotiate:
		return c.handleNegotiate(msg, hdr)
	case wire.CmdSessionSetup:
		return c.handleSessionSetup(ctx, msg, hdr)
	case wire.CmdLogoff:
		return c.handleLogoff(ctx, hdr, sess)
	case wire.CmdTreeConnect:
		return c.handleTreeConnect(msg, hdr, sess)
	case wire.CmdTreeDisconnect:
		return c.handleTreeDisconnect(ctx, hdr, sess, tr)
	case wire.CmdCreate:
		return c.handleCreate(ctx, msg, hdr, tr, lastFileId)
	case wire.CmdClose:
		return c.handleClose(ctx, msg, tr)
	case wire.CmdRead:
		return c.handleRead(ctx, msg, tr)
	case wire.CmdWrite:
		return c.handleWrite(ctx, msg, tr)
	case wire.CmdQueryDirectory:
		return c.handleQueryDirectory(ctx, msg, tr)
	case wire.CmdQueryInfo:
		return c.handleQueryInfo(ctx, msg, tr)
	case wire.CmdSetInfo:
		return c.handleSetInfo(ctx, msg, tr)
	case wire.CmdFlush:
		return c.handleFlush(ctx, msg, tr)
	case wire.CmdLock:
		return c.handleLock(ctx, msg, hdr, tr)
	case wire.CmdIoctl:
		return c.handleIoctl(ctx, msg, tr)
	case wire.CmdEcho:
		return c.handleEcho(hdr)
	case wire.CmdOplockBreak:
		return c.handleOplockBreak(msg)
	default:
		return c.errBody(wire.StatusNotImplemented)
	}
}

func requiresSession(cmd uint16) bool {
	switch cmd {
	case wire.CmdNegotiate:
		return false
	default:
		return true
	}
}

func requiresTree(cmd uint16) bool {
	switch cmd {
	case wire.CmdTreeConnect, wire.CmdSessionSetup, wire.CmdLogoff, wire.CmdEcho, wire.CmdNegotiate:
		return false
	default:
		return true
	}
}

func (c *request) errBody(status uint32) uint32 {
	var e wire.ErrorResponse
	c.out = e.Append(c.out)
	return status
}

func (c *request) handleNegotiate(msg []byte, hdr *wire.Header) uint32 {
	var req wire.NegotiateRequest
	if err := req.Parse(msg[wire.HeaderSize:]); err != nil {
		return c.errBody(wire.StatusInvalidParameter)
	}
	dialect := pickDialect(req.Dialects, c.srv.dialect)
	if dialect == 0 {
		return c.errBody(wire.StatusNotSupported)
	}

	caps := c.negotiateCapabilities()
	c.negDialect = dialect
	c.negCaps = caps

	resp := wire.NegotiateResponse{
		SecurityMode:    wire.SigningEnabled,
		DialectRevision: dialect,
		ServerGuid:      c.srv.guid,
		Capabilities:    caps,
		MaxTransactSize: c.srv.maxTransact,
		MaxReadSize:     c.srv.maxRead,
		MaxWriteSize:    c.srv.maxWrite,
		SecurityBuffer:  ntlmssp.NegTokenInitNTLM(),
	}
	if c.srv.requireEnc && dialect >= wire.DialectSMB30 {
		resp.Contexts = append(resp.Contexts, wire.NegotiateContext{
			Type: wire.CtxEncryption,
			Data: []byte{0x01, 0x00,
				0x01, 0x00},
		})
	}
	if dialect == wire.DialectSMB311 {
		resp.Contexts = append(resp.Contexts, wire.NegotiateContext{
			Type: wire.CtxPreauthIntegrity,
			Data: []byte{0x01, 0x00,
				0x00, 0x00,
				0x01, 0x00},
		})
	}
	c.out = resp.Append(c.out)
	return wire.StatusSuccess
}

func pickDialect(offered []uint16, maxDialect uint16) uint16 {
	var best uint16
	for _, d := range offered {
		if d > maxDialect {
			continue
		}
		if d == wire.DialectSMB202 || d == wire.DialectSMB21 ||
			d == wire.DialectSMB30 || d == wire.DialectSMB302 || d == wire.DialectSMB311 {
			if d > best {
				best = d
			}
		}
	}
	return best
}

func (c *request) handleSessionSetup(ctx context.Context, msg []byte, hdr *wire.Header) uint32 {
	var req wire.SessionSetupRequest
	if err := req.Parse(msg); err != nil {
		return c.errBody(wire.StatusInvalidParameter)
	}
	sess := c.getSession(hdr.SessionId)
	if sess == nil {
		sess = &session{
			auth:  c.srv.authFactory(),
			trees: make(map[uint32]*tree),
		}
		c.nextSess++
		sessID := c.nextSess
		c.putSession(sessID, sess)
		hdr.SessionId = sessID
	}

	result, err := sess.auth.Accept(ctx, req.SecurityBuffer)
	if err != nil {
		if errors.Is(err, auth.ErrLogonFailed) {
			return c.errBody(wire.StatusLogonFailure)
		}
		return c.errBody(wire.StatusAccessDenied)
	}

	ssr := wire.SessionSetupResponse{
		SecurityBuffer: result.OutputToken,
	}
	if c.srv.requireEnc {
		ssr.SessionFlags |= wire.SessionFlagEncryptData
	}
	if result.Identity != nil {
		sess.identity = result.Identity
		sess.authenticated = true
		sess.signer, _ = signing.NewSigner(signing.DeriveSigningKey(result.SessionKey))
		sess.encryptionKey = encryption.DeriveServerEncryptionKey(result.SessionKey)
		sess.decryptionKey = encryption.DeriveServerDecryptionKey(result.SessionKey)
		sess.requireEncrypt = c.srv.requireEnc
	}
	c.out = ssr.Append(c.out)
	if sess.authenticated {
		return wire.StatusSuccess
	}
	return wire.StatusMoreProcessingRequired
}

func (c *request) handleLogoff(ctx context.Context, hdr *wire.Header, sess *session) uint32 {
	if sess != nil {
		for _, t := range sess.allTrees() {
			c.closeAllOpens(ctx, t)
		}
		c.dropSession(hdr.SessionId)
	}
	var r wire.LogoffResponse
	c.out = r.Append(c.out)
	return wire.StatusSuccess
}

func (c *request) handleTreeConnect(msg []byte, hdr *wire.Header, sess *session) uint32 {
	var req wire.TreeConnectRequest
	if err := req.Parse(msg); err != nil {
		return c.errBody(wire.StatusInvalidParameter)
	}
	shareName := parseShareName(wire.UTF16FromBytes(req.Path))
	sh, ok := c.srv.shareByName[shareName]
	if !ok {
		return c.errBody(wire.StatusBadNetworkName)
	}

	treeID := sess.nextTreeID
	sess.nextTreeID++
	sess.addTree(treeID, &tree{
		share: sh,
		opens: make(map[[16]byte]*openHandle),
	})
	hdr.TreeId = treeID

	resp := wire.TreeConnectResponse{
		ShareType:     wire.ShareTypeDisk,
		ShareFlags:    0x00000030,
		Capabilities:  0,
		MaximalAccess: 0x001f01ff,
	}
	c.out = resp.Append(c.out)
	return wire.StatusSuccess
}

func parseShareName(unc string) string {
	s := strings.TrimLeft(unc, `\`)
	if i := strings.IndexByte(s, '\\'); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.IndexByte(s, '\\'); i >= 0 {
		s = s[:i]
	}
	return s
}

func (c *request) handleTreeDisconnect(ctx context.Context, hdr *wire.Header, sess *session, tr *tree) uint32 {
	if tr != nil {
		c.closeAllOpens(ctx, tr)
		sess.dropTree(hdr.TreeId)
	}
	var r wire.TreeDisconnectResponse
	c.out = r.Append(c.out)
	return wire.StatusSuccess
}

func (c *conn) closeAllOpens(ctx context.Context, tr *tree) {
	for _, oh := range tr.allOpens() {
		c.srv.lockTable().ReleaseOwner(lockOwner(oh.sessionID, oh.fileId))
		_ = oh.h.Close(ctx)
	}
	tr.opens = make(map[[16]byte]*openHandle)
}

func (c *request) handleCreate(ctx context.Context, msg []byte, hdr *wire.Header, tr *tree, lastFileId *[16]byte) uint32 {
	var req wire.CreateRequest
	if err := req.Parse(msg); err != nil {
		return c.errBody(wire.StatusInvalidParameter)
	}
	name := wire.UTF16FromBytes(req.Name)
	opts := vfs.OpenOptions{
		Path:          name,
		Disposition:   req.CreateDisposition,
		CreateDir:     req.CreateOptions&wire.FileDirectoryFile != 0,
		DesiredAccess: req.DesiredAccess,
		ShareAccess:   req.ShareAccess,
		DeleteOnClose: req.CreateOptions&wire.FileDeleteOnClose != 0,
	}
	h, err := tr.share.Backend().Open(ctx, opts)
	if err != nil {
		return c.errBody(osErrToStatus(err))
	}
	fi, err := h.Stat(ctx)
	if err != nil {
		_ = h.Close(ctx)
		return c.errBody(osErrToStatus(err))
	}

	fid := makeFileID(hdr.SessionId, hdr.TreeId, tr.nextFileID())
	c.log.Debug("create", "path", name, "disposition", req.CreateDisposition,
		"desired_access", req.DesiredAccess, "options", req.CreateOptions)
	oh := &openHandle{h: h, fileId: fid, sessionID: hdr.SessionId, path: name,
		deletePending: req.CreateOptions&wire.FileDeleteOnClose != 0}
	tr.addOpen(oh)
	*lastFileId = fid

	// CreateAction tells the client what the open actually did (MS-SMB2
	// section 2.2.14).
	action := wire.FileOpened
	switch req.CreateDisposition {
	case wire.FileCreate:
		action = wire.FileCreated
	case wire.FileSupersede:
		action = wire.FileSuperseded
	case wire.FileOverwrite:
		action = wire.FileOverwritten
	case wire.FileOverwriteIf:
		action = wire.FileOverwritten
	}

	// Grant no oplock. Granting one lets the client cache the file and write
	// its cached copy back later, but breaking an oplock is not implemented
	// here, and the same objects are also reachable over NFS and directly in
	// the object store. With no oplock, clients write through: Windows
	// PowerShell's Set-Content otherwise flushed stale cached content and
	// silently appended to files instead of replacing them.
	var oplock uint8

	resp := wire.CreateResponse{
		OplockLevel:    oplock,
		CreateAction:   action,
		CreationTime:   wire.TimeToFiletime(fi.CreationTime),
		LastAccessTime: wire.TimeToFiletime(fi.LastAccess),
		LastWriteTime:  wire.TimeToFiletime(fi.LastWrite),
		ChangeTime:     wire.TimeToFiletime(fi.ChangeTime),
		AllocationSize: uint64(fi.Size),
		EndOfFile:      uint64(fi.Size),
		FileAttributes: toFileAttributes(fi),
		FileId:         fid,
	}
	c.out = resp.Append(c.out)
	return wire.StatusSuccess
}

// DOS attribute bits (MS-FSCC section 2.6).
const (
	attrReadOnly  uint32 = 0x00000001
	attrHidden    uint32 = 0x00000002
	attrSystem    uint32 = 0x00000004
	attrDirectory uint32 = 0x00000010
	attrArchive   uint32 = 0x00000020
	attrNormal    uint32 = 0x00000080
)

// toFileAttributes reports the backend's attributes, with the directory bit
// forced to match the entry itself. A file with no stored attributes is
// reported as FILE_ATTRIBUTE_ARCHIVE, which is what Windows servers and
// Samba report for an ordinary file.
func toFileAttributes(fi vfs.FileInfo) uint32 {
	attrs := fi.Attributes & (attrReadOnly | attrHidden | attrSystem | attrArchive)
	if fi.IsDir {
		return attrs | attrDirectory
	}
	if attrs == 0 {
		return attrArchive
	}
	return attrs
}

func (c *request) handleClose(ctx context.Context, msg []byte, tr *tree) uint32 {
	var req wire.CloseRequest
	if err := req.Parse(msg); err != nil {
		return c.errBody(wire.StatusInvalidParameter)
	}
	oh, ok := tr.open(req.FileId)
	if !ok {
		return c.errBody(wire.StatusInvalidHandle)
	}
	fi, statErr := oh.h.Stat(ctx)
	if err := oh.h.Close(ctx); err != nil && statErr == nil {
		return c.errBody(osErrToStatus(err))
	}
	tr.removeOpen(req.FileId)
	if tr.oplocks != nil {
		tr.oplocks.release(oh.path)
	}

	if oh.deletePending {
		if rm, ok := tr.share.Backend().(vfs.Remover); ok {
			if rmErr := rm.Remove(ctx, oh.path); rmErr != nil {
				return c.errBody(osErrToStatus(rmErr))
			}
		}
	}

	resp := wire.CloseResponse{Flags: req.Flags & wire.CloseFlagPostQueryAttrib}
	if statErr == nil {
		resp.CreationTime = wire.TimeToFiletime(fi.CreationTime)
		resp.LastAccessTime = wire.TimeToFiletime(fi.LastAccess)
		resp.LastWriteTime = wire.TimeToFiletime(fi.LastWrite)
		resp.ChangeTime = wire.TimeToFiletime(fi.ChangeTime)
		resp.AllocationSize = uint64(fi.Size)
		resp.EndOfFile = uint64(fi.Size)
		resp.FileAttributes = toFileAttributes(fi)
	}
	c.out = resp.Append(c.out)
	return wire.StatusSuccess
}

func (c *request) handleRead(ctx context.Context, msg []byte, tr *tree) uint32 {
	var req wire.ReadRequest
	if err := req.Parse(msg); err != nil {
		return c.errBody(wire.StatusInvalidParameter)
	}
	oh, ok := tr.open(req.FileId)
	if !ok {
		return c.errBody(wire.StatusInvalidHandle)
	}
	respStart := len(c.out)
	c.out = wire.ReadResponseAlloc(c.out, int(req.Length))
	n, err := oh.h.Read(ctx, int64(req.Offset), wire.ReadResponseData(c.out, respStart))
	if err != nil && !errors.Is(err, errEOF) {
		c.out = c.out[:respStart]
		return c.errBody(osErrToStatus(err))
	}
	if n == 0 {
		c.out = c.out[:respStart]
		return c.errBody(wire.StatusEndOfFile)
	}
	c.out = wire.ReadResponseSetCount(c.out, respStart, n)
	return wire.StatusSuccess
}

func (c *request) handleWrite(ctx context.Context, msg []byte, tr *tree) uint32 {
	var req wire.WriteRequest
	if err := req.Parse(msg); err != nil {
		return c.errBody(wire.StatusInvalidParameter)
	}
	oh, ok := tr.open(req.FileId)
	if !ok {
		return c.errBody(wire.StatusInvalidHandle)
	}
	c.log.Debug("write", "path", oh.path, "offset", req.Offset, "len", len(req.Data))
	n, err := oh.h.Write(ctx, int64(req.Offset), req.Data)
	if err != nil {
		return c.errBody(osErrToStatus(err))
	}
	c.out = wire.WriteResponseAppend(c.out, uint32(n))
	return wire.StatusSuccess
}

func (c *request) handleQueryDirectory(ctx context.Context, msg []byte, tr *tree) uint32 {
	var req wire.QueryDirectoryRequest
	if err := req.Parse(msg); err != nil {
		return c.errBody(wire.StatusInvalidParameter)
	}
	oh, ok := tr.open(req.FileId)
	if !ok {
		return c.errBody(wire.StatusInvalidHandle)
	}

	oh.enumMu.Lock()
	defer oh.enumMu.Unlock()

	if req.Flags&(wire.QueryDirRestartScans|wire.QueryDirReopen) != 0 {
		oh.enumDone = false
		oh.enumStarted = false
	}
	if oh.enumDone {
		return c.errBody(wire.StatusNoMoreFiles)
	}

	pattern := wire.UTF16FromBytes(req.FileName)
	if pattern == "" {
		pattern = "*"
	}

	// Capture the listing on the first call, then serve it in batches: a
	// client that asked for a single entry comes back for the rest.
	if !oh.enumStarted {
		oh.enumEntries = oh.enumEntries[:0]
		oh.enumIndex = 0
		for fi, err := range oh.h.Enumerate(ctx, pattern) {
			if err != nil {
				return c.errBody(osErrToStatus(err))
			}
			oh.enumEntries = append(oh.enumEntries, fi)
		}
		oh.enumStarted = true
	}
	if oh.enumIndex >= len(oh.enumEntries) {
		oh.enumDone = true
		return c.errBody(wire.StatusNoMoreFiles)
	}

	// Encode the class the client asked for: each has a different fixed part
	// before the name, so answering in the wrong one gives clients garbled
	// names ("directory entry name would overflow", on Linux).
	infoClass := req.FileInformationClass
	entryMinSize, ok := wire.DirInfoFixedSize(infoClass)
	if !ok {
		return c.errBody(wire.StatusInvalidInfoClass)
	}

	const bodyFixed = 8
	bodyStart := len(c.out)
	c.out = append(c.out, make([]byte, bodyFixed)...)
	bufStart := len(c.out)

	var prevEntryStart = -1
	empty := true
	for ; oh.enumIndex < len(oh.enumEntries); oh.enumIndex++ {
		fi := oh.enumEntries[oh.enumIndex]
		if len(c.out)-bufStart+entryMinSize+len(fi.Name)*2 > int(req.OutputBufferLength) {
			if empty {
				// Not even one entry fits in the buffer the client offered.
				c.out = c.out[:bodyStart]
				return c.errBody(wire.StatusInfoLengthMismatch)
			}
			break
		}
		encFi := wire.FileInfo{
			Name:   fi.Name,
			FileId: pathIndexNumber(oh.path + "/" + fi.Name),
			// (pathIndexNumber normalizes separators, so this matches the
			// index a QUERY_INFO on the same file reports.)
			EndOfFile:      uint64(fi.Size),
			AllocationSize: uint64(fi.Size),
			FileAttributes: toFileAttributes(fi),
			CreationTime:   wire.TimeToFiletime(fi.CreationTime),
			LastAccessTime: wire.TimeToFiletime(fi.LastAccess),
			LastWriteTime:  wire.TimeToFiletime(fi.LastWrite),
			ChangeTime:     wire.TimeToFiletime(fi.ChangeTime),
		}
		var entryStart int
		c.out, entryStart = wire.AppendDirInfo(c.out, encFi, infoClass)
		if prevEntryStart >= 0 {
			wire.SetNextEntryOffset(c.out, prevEntryStart, entryStart)
		}
		prevEntryStart = entryStart
		empty = false
		if req.Flags&wire.QueryDirReturnSingle != 0 {
			// The client asked for one entry and will come back for more.
			oh.enumIndex++
			break
		}
	}

	if empty {
		c.out = c.out[:bodyStart]
		oh.enumDone = true
		return c.errBody(wire.StatusNoMoreFiles)
	}

	bufLen := len(c.out) - bufStart
	binary.LittleEndian.PutUint16(c.out[bodyStart:bodyStart+2], 9)
	// OutputBufferOffset is relative to this message's header, which is 64
	// bytes before the body, plus the 8-byte fixed part.
	binary.LittleEndian.PutUint16(c.out[bodyStart+2:bodyStart+4], wire.HeaderSize+8)
	binary.LittleEndian.PutUint32(c.out[bodyStart+4:bodyStart+8], uint32(bufLen))
	return wire.StatusSuccess
}

func (c *request) handleEcho(hdr *wire.Header) uint32 {
	c.out = append(c.out, 0x04, 0x00, 0x00, 0x00)
	return wire.StatusSuccess
}
