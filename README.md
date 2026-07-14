# go-smb-server

A from-scratch SMB2/3 server library in Go, built directly from the
[Microsoft Open Specifications](specs/). Export any filesystem backend over SMB
with pluggable authentication (Kerberos, NTLMv2, relay, or custom).

This is a library, not a Samba replacement. It provides a clean VFS and auth
boundary so you can serve any backend (local disk, in-memory, object store,
custom content store) and authenticate against any credential source.

## Status

Full SMB2/3 file serving — all core commands, signing, encryption, oplocks,
preauth integrity — tested against smbclient (Samba 4.24) and the go-smb2
reference client.

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
srv.ListenAndServe(ctx)  // blocks until ctx is cancelled
```

Runnable examples at [`examples/`](examples/).

## Documentation

| Document | Covers |
|----------|--------|
| [Server configuration](docs/server.md) | `server.New()`, options, `Shutdown()` |
| [Authentication](docs/auth.md) | `Authenticator`, NTLMSSP, Kerberos, relay auth, LDAP |
| [Virtual filesystem](docs/vfs.md) | `Backend`, `Handle`, optional interfaces, `PipeBackend` |
| [Encryption & signing](docs/encryption.md) | SMB3 AES-128-CCM, signing, `Signer` type |
| [Protocol support](docs/protocol.md) | Commands, dialects, FSCTLs, oplocks, preauth |

## Architecture

```
┌─────────────────────────────────────────┐
│                smb/server               │
│  listener, session state, credit mgmt,  │
│  signing, encryption, async framework   │
├──────────────┬──────────────────────────┤
│  smb/auth    │      smb/vfs             │
│ Authenticator│  Backend / Handle / Share│
│ RelayAuth    │  PipeBackend             │
├──────────────┴──────────────────────────┤
│              smb/wire                   │
│  SMB2 header, all command codecs,       │
│  FSCC info structures, NTSTATUS codes   │
├─────────────────────────────────────────┤
│         smb/transport                   │
│  Direct-TCP framing (FramedConn)        │
└─────────────────────────────────────────┘

Supporting packages:
  smb/ntlmssp    — NTLMv2 protocol implementation
  smb/signing    — AES-128-CMAC and HMAC-SHA256 signing
  smb/encryption — AES-128-CCM message encryption
```

## Design

- **Zero-allocation hot paths**. READ writes directly into the response buffer; CCM
  encrypts in-place; header encode/parse is allocation-free.
- **Caller-owned buffers**. Encoding uses `Append(b []byte) []byte` — the caller
  allocates and the encoder appends. Zero-copy parsing aliases the message buffer.
- **Pluggable boundaries**. Two interfaces drive all extensibility:
  `auth.Authenticator` (who can connect) and `vfs.Backend` (what they see).
- **NTLMv2 only**. NTLMv1 is intentionally not supported per MS-NLMP.
- **Leak-free**. Per-connection context, automatic cleanup on disconnect,
  non-blocking async sends. Verified by leak-detection tests.

## Tested clients

| Client | Auth | Encryption | Operations verified |
|--------|------|------------|---------------------|
| `go-smb2` (reference) | NTLMv2 | AES-128-CCM | Full interop |
| `smbclient` (Samba 4.24) | NTLMv2 | — | ls, get, put, mkdir, rm, rmdir |
| `smbclient` share enum | NTLMv2 | — | BIND succeeds, NDR share listing in progress |

## Performance (i5-7300HQ, 4KB payload)

| Operation | Throughput | Allocs |
|-----------|-----------|--------|
| CCM Seal | 203 MB/s | 8 |
| CCM Open | 235 MB/s | 7 |
| CMAC Sign | 446 MB/s | 4 |
| Header encode | — | 0 |
| Header parse | — | 0 |
| READ response | 47 GB/s | 0 |

## License

MIT. See [LICENSE](LICENSE).
