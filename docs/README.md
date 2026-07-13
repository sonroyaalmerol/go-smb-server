# go-smb-server — Documentation

An SMB2/3 server library for Go. Export any filesystem backend over SMB with pluggable authentication. Built from the [Microsoft Open Specifications](../specs/).

## Quick start

```go
package main

import (
    "context"
    "log/slog"
    "os/signal"
    "syscall"

    "github.com/sonroyaalmerol/go-smb-server/smb/server"
    "github.com/sonroyaalmerol/go-smb-server/smb/vfs"
)

func main() {
    backend, _ := vfs.NewLocalBackend("/path/to/share")
    srv, _ := server.New(
        server.WithAddr(":445"),
        server.WithShares(vfs.NewDiskShare("myshare", backend)),
    )
    ctx, _ := signal.NotifyContext(context.Background(), syscall.SIGINT)
    srv.ListenAndServe(ctx)
}
```

This starts an SMB3 server on port 445 serving `/path/to/share` as `\\server\myshare` with guest (no-op) authentication.

## Documentation index

| Document | Covers |
|----------|--------|
| [Server configuration](server.md) | `server.New()`, options, dialects, credits |
| [Authentication](auth.md) | `auth.Authenticator`, NTLMSSP, LDAP-backed auth |
| [Virtual filesystem](vfs.md) | `vfs.Backend`, `vfs.Handle`, local and custom backends |
| [Encryption & signing](encryption.md) | SMB3 AES-128-CCM, signing algorithms, key derivation |
| [Protocol support](protocol.md) | Supported commands, dialects, status codes, FSCTLs |
| [Examples](../examples/) | Runnable example servers |

## Architecture

```
┌─────────────────────────────────────────┐
│                smb/server               │
│  listener, session state, credit mgmt,  │
│  signing, encryption, async framework   │
├──────────────┬──────────────────────────┤
│  smb/auth    │      smb/vfs             │
│ Authenticator│  Backend / Handle / Share│
├──────────────┴──────────────────────────┤
│              smb/wire                   │
│  SMB2 header, all command codecs,       │
│  FSCC info structures, NTSTATUS codes   │
├─────────────────────────────────────────┤
│         smb/transport                   │
│  Direct-TCP framing (FramedConn)        │
└─────────────────────────────────────────┘

Supporting packages:
  smb/ntlmssp   — NTLMv2 protocol implementation
  smb/signing   — AES-128-CMAC and HMAC-SHA256 signing
  smb/encryption — AES-128-CCM message encryption
```

## Key design decisions

- **Caller-owned buffers**. Encoding uses `Append(b []byte) []byte` patterns — the caller allocates and the encoder appends. Zero-copy parsing aliases the message buffer.
- **Pluggable boundaries**. Two interfaces drive all extensibility: `auth.Authenticator` (who can connect) and `vfs.Backend` (what they see).
- **NTLMv2 only**. NTLMv1 is intentionally not supported per MS-NLMP security guidance.
- **AES-128-CMAC signing**. For SMB 3.x, the signing key is derived via SP800-108 KDF (Counter Mode) from the NTLM session key.
- **AES-128-CCM encryption**. From-scratch implementation validated against RFC 3610 test vectors.

## Tested clients

| Client | Auth | Encryption | Status |
|--------|------|------------|--------|
| `go-smb2` (reference) | NTLMv2 | AES-128-CCM | ✅ Full interop |
| `smbclient` (Samba 4.24) | NTLMv2 | — | ✅ ls, get, put, mkdir, rm, rmdir |
| Windows Explorer | NTLMv2 | AES-128-CCM | ⚠️ Requires DCE/RPC SRVSVC (not yet implemented) |
| macOS Finder | — | — | Not yet tested |
| `mount -t cifs` (Linux) | — | — | Not yet tested |
