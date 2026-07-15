package server

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"

	"github.com/sonroyaalmerol/go-smb-server/smb/auth"
	"github.com/sonroyaalmerol/go-smb-server/smb/encryption"
	"github.com/sonroyaalmerol/go-smb-server/smb/signing"
	"github.com/sonroyaalmerol/go-smb-server/smb/vfs"
	"github.com/sonroyaalmerol/go-smb-server/smb/wire"
)

func (c *conn) dispatch(ctx context.Context, msg []byte, hdr *wire.Header, lastFileId *[16]byte, related bool) uint32 {
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
		return c.handleLogoff(hdr, sess)
	case wire.CmdTreeConnect:
		return c.handleTreeConnect(msg, hdr, sess)
	case wire.CmdTreeDisconnect:
		return c.handleTreeDisconnect(hdr, sess, tr)
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
		return c.handleLock(ctx, msg, tr)
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

func (c *conn) errBody(status uint32) uint32 {
	var e wire.ErrorResponse
	c.out = e.Append(c.out)
	return status
}

func (c *conn) handleNegotiate(msg []byte, hdr *wire.Header) uint32 {
	var req wire.NegotiateRequest
	if err := req.Parse(msg[wire.HeaderSize:]); err != nil {
		return c.errBody(wire.StatusInvalidParameter)
	}
	dialect := pickDialect(req.Dialects, c.srv.dialect)
	if dialect == 0 {
		return c.errBody(wire.StatusNotSupported)
	}

	resp := wire.NegotiateResponse{
		SecurityMode:    wire.SigningEnabled,
		DialectRevision: dialect,
		ServerGuid:      c.srv.guid,
		Capabilities:    c.negotiateCapabilities(),
		MaxTransactSize: c.srv.maxTransact,
		MaxReadSize:     c.srv.maxRead,
		MaxWriteSize:    c.srv.maxWrite,
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

func (c *conn) handleSessionSetup(ctx context.Context, msg []byte, hdr *wire.Header) uint32 {
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
		c.sessions[sessID] = sess
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
		sess.signer, _ = signing.NewSigner(signing.DeriveSigningKey(result.SessionKey), signing.AlgoAESCMAC)
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

func (c *conn) handleLogoff(hdr *wire.Header, sess *session) uint32 {
	if sess != nil {
		for _, t := range sess.trees {
			c.closeAllOpens(t)
		}
		delete(c.sessions, hdr.SessionId)
	}
	var r wire.LogoffResponse
	c.out = r.Append(c.out)
	return wire.StatusSuccess
}

func (c *conn) handleTreeConnect(msg []byte, hdr *wire.Header, sess *session) uint32 {
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
	sess.trees[treeID] = &tree{
		share: sh,
		opens: make(map[[16]byte]*openHandle),
		locks: newLockMgrSet(),
	}
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

func (c *conn) handleTreeDisconnect(hdr *wire.Header, sess *session, tr *tree) uint32 {
	if tr != nil {
		c.closeAllOpens(tr)
		delete(sess.trees, hdr.TreeId)
	}
	var r wire.TreeDisconnectResponse
	c.out = r.Append(c.out)
	return wire.StatusSuccess
}

func (c *conn) closeAllOpens(tr *tree) {
	ctx := context.Background()
	for _, oh := range tr.opens {
		_ = oh.h.Close(ctx)
	}
	tr.opens = make(map[[16]byte]*openHandle)
}

func (c *conn) handleCreate(ctx context.Context, msg []byte, hdr *wire.Header, tr *tree, lastFileId *[16]byte) uint32 {
	var req wire.CreateRequest
	if err := req.Parse(msg); err != nil {
		return c.errBody(wire.StatusInvalidParameter)
	}
	name := wire.UTF16FromBytes(req.Name)
	opts := vfs.OpenOptions{
		Path:        name,
		Disposition: req.CreateDisposition,
		CreateDir:   req.CreateOptions&wire.FileDirectoryFile != 0,
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

	tr.nextID++
	fid := makeFileID(hdr.SessionId, hdr.TreeId, tr.nextID)
	oh := &openHandle{h: h, fileId: fid, path: name, deletePending: req.CreateOptions&wire.FileDeleteOnClose != 0}
	tr.opens[fid] = oh
	*lastFileId = fid

	action := wire.FileOpened
	switch req.CreateDisposition {
	case wire.FileCreate:
		action = wire.FileCreated
	case wire.FileSupersede, wire.FileOverwriteIf:
		action = wire.FileOverwritten
	}

	var oplock uint8
	if req.RequestedOplockLevel != 0 {
		if tr.oplocks == nil {
			tr.oplocks = newOplockTable()
		}
		info := &oplockInfo{fileId: fid, sessID: hdr.SessionId, treeID: hdr.TreeId, path: name}
		if tr.oplocks.grant(name, info) {
			oplock = req.RequestedOplockLevel
		} else {
			if broken := tr.oplocks.breakOplock(name); broken != nil {
				c.sendOplockBreak(broken)
			}
		}
	}

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

func toFileAttributes(fi vfs.FileInfo) uint32 {
	if fi.IsDir {
		return 0x10
	}
	return 0x20
}

func (c *conn) handleClose(ctx context.Context, msg []byte, tr *tree) uint32 {
	var req wire.CloseRequest
	if err := req.Parse(msg); err != nil {
		return c.errBody(wire.StatusInvalidParameter)
	}
	oh, ok := tr.opens[req.FileId]
	if !ok {
		return c.errBody(wire.StatusInvalidHandle)
	}
	fi, statErr := oh.h.Stat(ctx)
	if err := oh.h.Close(ctx); err != nil && statErr == nil {
		return c.errBody(osErrToStatus(err))
	}
	delete(tr.opens, req.FileId)
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

func (c *conn) handleRead(ctx context.Context, msg []byte, tr *tree) uint32 {
	var req wire.ReadRequest
	if err := req.Parse(msg); err != nil {
		return c.errBody(wire.StatusInvalidParameter)
	}
	oh, ok := tr.opens[req.FileId]
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

func (c *conn) handleWrite(ctx context.Context, msg []byte, tr *tree) uint32 {
	var req wire.WriteRequest
	if err := req.Parse(msg); err != nil {
		return c.errBody(wire.StatusInvalidParameter)
	}
	oh, ok := tr.opens[req.FileId]
	if !ok {
		return c.errBody(wire.StatusInvalidHandle)
	}
	n, err := oh.h.Write(ctx, int64(req.Offset), req.Data)
	if err != nil {
		return c.errBody(osErrToStatus(err))
	}
	c.out = wire.WriteResponseAppend(c.out, uint32(n))
	return wire.StatusSuccess
}

func (c *conn) handleQueryDirectory(ctx context.Context, msg []byte, tr *tree) uint32 {
	var req wire.QueryDirectoryRequest
	if err := req.Parse(msg); err != nil {
		return c.errBody(wire.StatusInvalidParameter)
	}
	oh, ok := tr.opens[req.FileId]
	if !ok {
		return c.errBody(wire.StatusInvalidHandle)
	}

	if req.Flags&(wire.QueryDirRestartScans|wire.QueryDirReopen) != 0 {
		oh.enumDone = false
	}
	oh.enumMu.Lock()
	defer oh.enumMu.Unlock()
	if oh.enumDone {
		return c.errBody(wire.StatusNoMoreFiles)
	}

	pattern := wire.UTF16FromBytes(req.FileName)
	if pattern == "" {
		pattern = "*"
	}

	useFileIdBothDir := req.FileInformationClass == wire.FileIdBothDirectoryInformation
	entryMinSize := wire.FileDirInfoMinSize
	encoder := wire.AppendFileDirInfo
	if useFileIdBothDir {
		entryMinSize = wire.FileIdBothDirInfoMinSize
		encoder = wire.AppendFileIdBothDirInfo
	}

	const bodyFixed = 8
	bodyStart := len(c.out)
	c.out = append(c.out, make([]byte, bodyFixed)...)
	bufStart := len(c.out)

	var prevEntryStart int = -1
	empty := true
	for fi, err := range oh.h.Enumerate(ctx, pattern) {
		if err != nil {
			if empty {
				c.out = c.out[:bodyStart]
				return c.errBody(osErrToStatus(err))
			}
			break
		}
		if len(c.out)-bufStart+entryMinSize+len(fi.Name)*2 > int(req.OutputBufferLength) {
			break
		}
		encFi := wire.FileInfo{
			Name:           fi.Name,
			EndOfFile:      uint64(fi.Size),
			AllocationSize: uint64(fi.Size),
			FileAttributes: toFileAttributes(fi),
			CreationTime:   wire.TimeToFiletime(fi.CreationTime),
			LastAccessTime: wire.TimeToFiletime(fi.LastAccess),
			LastWriteTime:  wire.TimeToFiletime(fi.LastWrite),
			ChangeTime:     wire.TimeToFiletime(fi.ChangeTime),
		}
		var entryStart int
		c.out, entryStart = encoder(c.out, encFi)
		if prevEntryStart >= 0 {
			wire.SetNextEntryOffset(c.out, prevEntryStart, entryStart)
		}
		prevEntryStart = entryStart
		empty = false
	}

	if empty {
		c.out = c.out[:bodyStart]
		return c.errBody(wire.StatusNoMoreFiles)
	}

	bufLen := len(c.out) - bufStart
	binary.LittleEndian.PutUint16(c.out[bodyStart:bodyStart+2], 9)
	binary.LittleEndian.PutUint16(c.out[bodyStart+2:bodyStart+4], uint16(bufStart))
	binary.LittleEndian.PutUint32(c.out[bodyStart+4:bodyStart+8], uint32(bufLen))
	oh.enumDone = true
	return wire.StatusSuccess
}

func (c *conn) handleEcho(hdr *wire.Header) uint32 {
	c.out = append(c.out, 0x04, 0x00, 0x00, 0x00)
	return wire.StatusSuccess
}
