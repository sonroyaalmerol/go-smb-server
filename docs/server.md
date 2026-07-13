# Server Configuration

The `smb/server` package is the top-level entry point. Create a server with `server.New()` and functional options.

## Creating a server

```go
srv, err := server.New(opts ...Option)
if err != nil {
    log.Fatal(err)
}
srv.ListenAndServe(ctx) // blocks until ctx is cancelled
```

## Options

### `WithAddr(addr string)`

TCP listen address. Default: `":445"`.

```go
server.WithAddr(":1445") // high port for testing without root
server.WithAddr("0.0.0.0:445")
```

### `WithShares(shares ...vfs.Share)`

Register one or more shares. Each share has a name and a filesystem backend.

```go
server.WithShares(
    vfs.NewDiskShare("documents", docsBackend),
    vfs.NewDiskShare("media", mediaBackend),
)
```

### `WithAuth(f auth.Factory)`

Set the authentication provider. The factory is called per-connection to create a fresh `Authenticator` for each session setup. Default: `auth.AlwaysAllowFactory()` (guest access).

See [Authentication](auth.md) for details.

```go
creds := ntlmssp.NewMemoryCredentials()
creds.Add("DOMAIN", "user", "password")
server.WithAuth(ntlmssp.NewServer(creds, "SERVERNAME"))
```

### `WithDialect(d uint16)`

Maximum SMB dialect to negotiate. Default: `wire.DialectSMB302` (SMB 3.0.2).

```go
server.WithDialect(wire.DialectSMB311) // SMB 3.1.1
server.WithDialect(wire.DialectSMB30)  // SMB 3.0
```

### `WithMaxCredits(n uint32)`

Maximum credits granted to the client. Credits control concurrency — higher values allow the client to pipeline more requests. Default: 8192.

```go
server.WithMaxCredits(16384)
```

### `WithEncryptionRequired()`

Require all sessions to use AES-128-CCM encryption. The server advertises `CapEncryption` in the negotiate response and sets `SessionFlagEncryptData` on session setup. Plaintext messages on encrypted sessions are dropped.

### `WithLogger(l *slog.Logger)`

Structured logger for diagnostic output. Default: `slog.Default()`.

```go
server.WithLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
    Level: slog.LevelDebug,
})))
```

## Complete example with NTLM auth + encryption

```go
srv, err := server.New(
    server.WithAddr(":445"),
    server.WithShares(vfs.NewDiskShare("data", backend)),
    server.WithAuth(ntlmssp.NewServer(creds, "FILESRV")),
    server.WithEncryptionRequired(),
    server.WithLogger(slog.Default()),
)
```

## Compound requests

The server supports SMB2 compound (chained) requests. Multiple commands in a single transport frame are processed sequentially. `FlagRelatedOps` causes `FileId` to be forwarded from the previous operation. `STATUS_SUCCESS` on all sub-requests returns the full chain; a failure short-circuits remaining sub-requests with the error status.

## Credit accounting

Each request consumes credits based on `CreditCharge`. The server deducts credits on receive and replenishes to `maxCredits` on respond. The performance lever — higher credit windows enable multi-credit I/O for large transfers.
