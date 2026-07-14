# Virtual Filesystem (VFS)

The VFS is the second pluggable boundary. Implement `vfs.Backend` and
`vfs.Handle` to serve any storage backend.

## Core interfaces

### Share

```go
type Share interface {
    Name() string
    Backend() Backend
}
```

`DiskShare` is the standard implementation:

```go
share := vfs.NewDiskShare("documents", myBackend)
```

### Backend

```go
type Backend interface {
    Open(ctx context.Context, opts OpenOptions) (Handle, error)
}
```

Every CREATE goes through `Open`. `OpenOptions` carries path, disposition, and
create flags.

### Handle

```go
type Handle interface {
    Read(ctx context.Context, offset int64, p []byte) (int, error)
    Write(ctx context.Context, offset int64, p []byte) (int, error)
    Close(ctx context.Context) error
    Stat(ctx context.Context) (FileInfo, error)
    Enumerate(ctx context.Context, pattern string) iter.Seq2[FileInfo, error]
}
```

## Optional interfaces

Implement these for richer functionality. `LocalBackend` implements all.

| Interface | Method | Enables |
|-----------|--------|---------|
| `Remover` | `Remove(ctx, path) error` | Delete-on-close |
| `SetInfoer` | `SetInfo(ctx, *SetInfoRequest) error` | Timestamps, truncation, attributes |
| `Renamer` | `Rename(ctx, newPath, replace) error` | File rename |
| `Mkdirer` | `Mkdir(ctx, path) error` | Backend-level directory creation |
| `Copier` | `CopyChunk(ctx, src, offsets) error` | Server-side copy |
| `PipeProcessor` | `ProcessPipe(ctx, input) []byte` | Named pipe RPC |

### SetInfoRequest

```go
type SetInfoRequest struct {
    CreationTime   *time.Time
    LastAccessTime *time.Time
    LastWriteTime  *time.Time
    ChangeTime     *time.Time
    Attributes     *uint32
    EndOfFile      *int64
}
```

Nil fields mean "not changed".

## LocalBackend

Serves files from a local directory. Implements all optional interfaces.

```go
backend, err := vfs.NewLocalBackend("/path/to/root")
```

## PipeBackend (named pipes / DCE/RPC)

For SRVSVC share enumeration and other named pipe RPCs:

```go
pb := vfs.NewPipeBackend()
pb.Register("srvsvc", vfs.SrvsvcHandler(shareList))
share := vfs.NewDiskShare("IPC$", pb)
```

The server auto-registers `IPC$` with a `srvsvc` handler during `server.New()`.
The handler processes DCE/RPC BIND and NetrShareEnum requests.

`PipeProcessor` is the interface for custom pipe handlers — it receives raw
DCE/RPC input via `FSCTL_PIPE_TRANSCEIVE` and returns the response.

## Custom backend example

See [`examples/mem-backend`](../examples/mem-backend/) for a complete in-memory
VFS implementing `Backend`, `Handle`, `SetInfoer`, `Renamer`, and `Remover`.

## Enumerate with iter.Seq2

Go 1.23+ range-over-func for incremental directory listing:

```go
func (h *myHandle) Enumerate(ctx context.Context, pattern string) iter.Seq2[vfs.FileInfo, error] {
    return func(yield func(vfs.FileInfo, error) bool) {
        for _, entry := range h.entries {
            if !yield(entry, nil) { return }
        }
    }
}
```
