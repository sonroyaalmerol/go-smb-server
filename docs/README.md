# go-smb-server — Documentation

An SMB2/3 server library for Go. Export any filesystem backend over SMB with
pluggable authentication. Built from the [Microsoft Open Specifications](../specs/).

## Quick start

```go
backend, _ := vfs.NewLocalBackend("/data/share")
creds := ntlmssp.NewMemoryCredentials()
creds.Add("WORKGROUP", "alice", "secret")

srv, _ := server.New(
    server.WithAddr(":445"),
    server.WithShares(vfs.NewDiskShare("share", backend)),
    server.WithAuth(ntlmssp.NewServer(creds, "FILESRV")),
)
srv.ListenAndServe(ctx)
```

## Documentation index

| Document | Covers |
|----------|--------|
| [Server configuration](server.md) | `server.New()`, options, `Shutdown()`, compound requests |
| [Authentication](auth.md) | `Authenticator`, NTLMSSP, Kerberos, relay auth, LDAP, custom |
| [Virtual filesystem](vfs.md) | `Backend`, `Handle`, optional interfaces, `PipeBackend` |
| [Encryption & signing](encryption.md) | AES-128-CCM, `Signer` type, key derivation |
| [Protocol support](protocol.md) | Commands, dialects, FSCTLs, oplocks, preauth |
| [Examples](../examples/) | 7 runnable example servers |

## Key design decisions

- **Zero-allocation I/O**. READ writes directly into the response buffer. CCM
  encrypts/decrypts in-place. Header encode/parse allocates nothing.
- **Pluggable boundaries**. `auth.Authenticator` and `vfs.Backend` drive all
  extensibility. No Samba-style monolithic config.
- **NTLMv2 only**. NTLMv1 intentionally unsupported per MS-NLMP.
- **Leak-free**. Per-connection child context, automatic cleanup (handles,
  sessions, pending ops) on disconnect, non-blocking async channels.
- **AES-128-CMAC signing**. SP800-108 KDF derivation from NTLM session key.
- **AES-128-CCM encryption**. From-scratch, in-place, RFC 3610 validated.

## VFS optional interfaces

Backends implement `vfs.Backend` (required) plus any of these optional
interfaces for richer functionality:

| Interface | Methods | Enables |
|-----------|---------|---------|
| `Remover` | `Remove(ctx, path)` | Delete-on-close (SET_INFO FileDispositionInformation) |
| `SetInfoer` | `SetInfo(ctx, *SetInfoRequest)` | Timestamps, attributes, truncation (SET_INFO) |
| `Renamer` | `Rename(ctx, newPath, replace)` | File rename (SET_INFO FileRenameInformation) |
| `Mkdirer` | `Mkdir(ctx, path)` | Backend-level directory creation |
| `Copier` | `CopyChunk(ctx, src, offsets)` | Server-side copy (FSCTL_SRV_COPYCHUNK) |
| `PipeProcessor` | `ProcessPipe(ctx, input)` | Named pipe RPC (FSCTL_PIPE_TRANSCEIVE) |

`LocalBackend` implements all of these. Custom backends implement only what
they need.
