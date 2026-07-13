# go-smb-server

A from-scratch SMB2/3 server library in Go, built directly from the
[Microsoft Open Specifications](specs/). The goal: **export a filesystem over
SMB with pluggable authentication** (e.g. a non-Samba LDAP schema).

This is a library, not a Samba replacement. It provides a clean VFS and auth
boundary so you can serve any backend (local disk, in-memory, object store,
custom content store) and authenticate against any credential source.

## Status

Core SMB2/3 file serving is implemented and tested end-to-end:

- ✅ Direct-TCP / NetBIOS transport framing (MS-SMB2 §2.1)
- ✅ Packet codec: 64-byte header, NEGOTIATE, SESSION_SETUP, TREE_CONNECT /
  DISCONNECT, CREATE, READ, WRITE, CLOSE, QUERY_DIRECTORY, ECHO, LOGOFF
  (MS-SMB2 §2.2)
- ✅ Dialect negotiation (SMB 2.0.2 → 3.0.2)
- ✅ Pluggable authentication via SPNEGO/SESSION_SETUP (`auth.Authenticator`)
- ✅ Pluggable filesystem (`vfs.Backend`)
- ✅ Compounded & related requests (CREATE→WRITE→CLOSE in one frame)
  (MS-SMB2 §3.2.4.1.4, §3.3.5.2.7.2)
- ✅ FileDirectoryInformation enumeration (MS-FSCC §2.4.8)
- ✅ NTSTATUS error mapping (MS-ERREF)

Not yet implemented: signing/encryption, oplocks/leases, multi-channel, durable
handles, DCE/RPC share enumeration (SRVSVC), QUIC/RDMA transport. See
[specs/README.md](specs/README.md) for the full roadmap by tier.

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│  transport  │ ──▶ │     wire     │ ──▶ │   server     │
│  (framing)  │     │  (codec)     │     │  (dispatch)  │
└─────────────┘     └──────────────┘     └──────┬───────┘
                                                │
                          ┌─────────────────────┼─────────────────────┐
                          ▼                     ▼                     ▼
                   ┌─────────────┐      ┌──────────────┐      ┌──────────────┐
                   │    auth     │      │     vfs      │      │   fscc       │
                   │ (SPNEGO →   │      │ (Backend →   │      │ (info class  │
                   │  Authenticator)│   │   Handle)    │      │  encoders)   │
                   └─────────────┘      └──────────────┘      └──────────────┘
```

- **`smb/transport`** — Direct-TCP/NetBIOS framing with a pooled read buffer.
- **`smb/wire`** — Zero-copy packet codec (`Append`/`Parse` style; request
  structs alias the message buffer).
- **`smb/auth`** — The auth boundary. SESSION_SETUP's security buffer (a
  SPNEGO token) is handed to an `Authenticator` you provide. Implement this to
  validate against your LDAP schema.
- **`smb/vfs`** — The filesystem boundary. A `Backend` exposes a share's file
  tree; `Handle` is an open file/directory. `LocalBackend` serves a real disk.
- **`smb/server`** — Wires it together; negotiates, drives SESSION_SETUP, and
  serves commands with compounding support.

## Usage

```go
backend, _ := vfs.NewLocalBackend("/data/share")
srv, _ := server.New(
    server.WithAddr(":445"),
    server.WithShares(vfs.NewDiskShare("share", backend)),
    server.WithAuth(myLDAPAuthFactory),  // implement auth.Factory
)
srv.ListenAndServe(ctx)
```

A runnable example is at [`examples/localdisk`](examples/localdisk).

## Plugging in custom auth

`smb/auth.Authenticator` processes the SPNEGO token stream for one session.
For NTLMSSP, validate the challenge/response against your custom LDAP schema and
return an `auth.Identity`:

```go
type LDAPAuth struct { /* ... */ }

func (a *LDAPAuth) Accept(ctx context.Context, token []byte) (auth.AcceptResult, error) {
    // parse the SPNEGO/NTLMSSP token, validate against LDAP, return Identity
    // on success or auth.ErrLogonFailed
}

func NewLDAPAuthFactory() auth.Factory {
    return func() auth.Authenticator { return &LDAPAuth{...} }
}
```

Wire it with `server.WithAuth(NewLDAPAuthFactory())`. MS-NLMP (NTLMSSP) and
MS-SPNG (SPNEGO) are in `specs/` to guide the implementation.

## Plugging in a custom filesystem

Implement `vfs.Backend` (a single `Open` method returning a `vfs.Handle`).
`Handle` provides `Read`/`Write`/`Close`/`Stat`/`Enumerate`. `Read` takes a
caller-provided buffer so the server reads directly into the response buffer
with no extra copy; `Enumerate` yields entries via `iter.Seq2` so directory
listings fill the output buffer incrementally.

## Performance

The codec is allocation-light by design:

- Header is a value type; `Header.Append` / `Header.EncodeAt` write into a
  caller-provided buffer (no marshal-to-new-slice).
- Request structs alias the message buffer on parse (like `bufio.Scanner`).
- `FramedConn` reuses its read buffer across messages.
- Handlers write responses into a single reused per-connection output buffer.
- `vfs.Handle.Read(ctx, offset, p)` reads into the caller's buffer.
- Directory enumeration is incremental (`iter.Seq2`), stopping when the
  output buffer fills.

## Specs

The `specs/` directory contains the 28 relevant Microsoft Open Specifications,
indexed by tier in [specs/README.md](specs/README.md). Cite sections as
`MS-SMB2 §2.2.5`.

## License

Code: MIT. Specs: under Microsoft Open Specifications terms
(see [specs/SOURCES.md](specs/SOURCES.md)).
