# go-smb-server

A from-scratch SMB2/3 server library in Go, built directly from the
[Microsoft Open Specifications](specs/). The goal: **export a filesystem over
SMB with pluggable authentication** (e.g. a non-Samba LDAP schema).

This is a library, not a Samba replacement. It provides a clean VFS and auth
boundary so you can serve any backend (local disk, in-memory, object store,
custom content store) and authenticate against any credential source.

## Status

Full SMB2/3 file serving — all core commands, signing, and encryption —
tested against smbclient (Samba 4.24) and the go-smb2 reference client.

## Quick start

```go
backend, _ := vfs.NewLocalBackend("/data/share")
srv, _ := server.New(
    server.WithAddr(":445"),
    server.WithShares(vfs.NewDiskShare("share", backend)),
)
srv.ListenAndServe(ctx)
```

A runnable example is at [`examples/localdisk`](examples/localdisk).

## Documentation

| Document | Covers |
|----------|--------|
| [Server configuration](docs/server.md) | `server.New()`, options, dialects, credits |
| [Authentication](docs/auth.md) | `auth.Authenticator`, NTLMSSP, LDAP-backed auth |
| [Virtual filesystem](docs/vfs.md) | `vfs.Backend`, `vfs.Handle`, local and custom backends |
| [Encryption & signing](docs/encryption.md) | SMB3 AES-128-CCM, signing algorithms, key derivation |
| [Protocol support](docs/protocol.md) | Supported commands, dialects, status codes, FSCTLs |
| [Examples](examples/) | Runnable example servers |

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

## Design

- **Caller-owned buffers**. Encoding uses `Append(b []byte) []byte` patterns — the caller allocates and the encoder appends. Zero-copy parsing aliases the message buffer.
- **Pluggable boundaries**. Two interfaces drive all extensibility: `auth.Authenticator` (who can connect) and `vfs.Backend` (what they see).
- **NTLMv2 only**. NTLMv1 is intentionally not supported per MS-NLMP security guidance.
- **AES-128-CMAC signing**. For SMB 3.x, the signing key is derived via SP800-108 KDF (Counter Mode) from the NTLM session key.
- **AES-128-CCM encryption**. From-scratch implementation validated against RFC 3610 test vectors.

## Tested clients

| Client | Auth | Encryption | Operations verified |
|--------|------|------------|---------------------|
| `go-smb2` (reference) | NTLMv2 | AES-128-CCM | Full interop |
| `smbclient` (Samba 4.24) | NTLMv2 | — | ls, get, put, mkdir, rm, rmdir |
| `smbclient` share enum | NTLMv2 | — | ⚠️ IPC$+SRVSVC infrastructure ready, needs IOCTL debug |

## Specs

The `specs/` directory contains the 28 relevant Microsoft Open Specifications,
indexed by tier in [specs/README.md](specs/README.md). Cite sections as
`MS-SMB2 §2.2.5`.

## License

Code: MIT. Specs: under Microsoft Open Specifications terms
(see [specs/SOURCES.md](specs/SOURCES.md)).
