# Server Configuration

The `smb/server` package is the top-level entry point.

## Creating a server

```go
srv, err := server.New(opts ...server.Option)
if err != nil {
    log.Fatal(err)
}
srv.ListenAndServe(ctx) // blocks until ctx is cancelled
```

## Graceful shutdown

```go
// Method 1: context cancellation
ctx, cancel := context.WithCancel(context.Background())
go srv.ListenAndServe(ctx)
cancel() // triggers shutdown

// Method 2: explicit Shutdown (closes listener)
if err := srv.Shutdown(); err != nil {
    log.Fatal(err)
}
```

`Shutdown` closes the listener. Active connections finish their current
request, then the per-connection cleanup runs (closes all file handles,
cancels pending async operations, stops CHANGE_NOTIFY goroutines).

## Options

### `WithAddr(addr string)`

TCP listen address. Default: `:445`.

### `WithShares(shares ...vfs.Share)`

Register one or more shares. `IPC$` is auto-registered for share enumeration
via SRVSVC if not provided explicitly.

```go
server.WithShares(
    vfs.NewDiskShare("documents", docsBackend),
    vfs.NewDiskShare("media", mediaBackend),
)
```

### `WithAuth(f auth.Factory)`

Authentication provider. Default: guest (`auth.AlwaysAllowFactory`).

```go
creds := ntlmssp.NewMemoryCredentials()
creds.Add("WORKGROUP", "user", "password")
server.WithAuth(ntlmssp.NewServer(creds, "SERVERNAME"))
```

See [Authentication](auth.md) for relay auth and custom backends.

### `WithDialect(d uint16)`

Maximum SMB dialect. Default: `wire.DialectSMB302` (3.0.2).

### `WithMaxCredits(n uint32)`

Maximum credits granted per connection. Higher = more concurrent I/O.
Default: 8192.

### `WithEncryptionRequired()`

Require AES-128-CCM encryption on all sessions. Sets `SessionFlagEncryptData`
on SESSION_SETUP and drops plaintext messages on encrypted sessions.

### `WithLogger(l *slog.Logger)`

Structured logger. Default: `slog.Default()`.
