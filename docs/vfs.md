# Virtual Filesystem (VFS)

The VFS is the second pluggable boundary. Implement `vfs.Backend` and `vfs.Handle` to serve any storage backend: local disk, in-memory, S3, database, custom content store.

## Interfaces

### Share

```go
type Share interface {
    Name() string
    Backend() Backend
}
```

`DiskShare` is the standard implementation. Create one per shared directory:

```go
share := vfs.NewDiskShare("documents", myBackend)
```

### Backend

```go
type Backend interface {
    Open(ctx context.Context, opts OpenOptions) (Handle, error)
}
```

`Open` is the sole entry point. Every SMB CREATE, OPEN, or directory traversal goes through `Open`. The `OpenOptions` tell you what the client wants:

```go
type OpenOptions struct {
    Path        string // relative path within the share
    Disposition uint32 // create disposition
    CreateDir   bool   // FILE_DIRECTORY_FILE create option
    Append      bool   // FILE_APPEND_DATA desired access
}
```

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

- **Read/Write**: Positioned I/O. The server calls these for SMB2 READ and WRITE.
- **Close**: Called on SMB2 CLOSE. Clean up resources.
- **Stat**: Returns file metadata for QUERY_INFO and CREATE responses.
- **Enumerate**: Returns an iterator over directory entries matching a glob pattern. Used by QUERY_DIRECTORY.

### FileInfo

```go
type FileInfo struct {
    Name         string
    Size         int64
    IsDir        bool
    CreationTime time.Time
    LastAccess   time.Time
    LastWrite    time.Time
    ChangeTime   time.Time
}
```

### Remover (optional)

```go
type Remover interface {
    Remove(ctx context.Context, path string) error
}
```

If the backend implements `Remover`, delete-on-close operations (SET_INFO with `FileDispositionInformation`, or CREATE with `FileDeleteOnClose`) will call `Remove` when the handle is closed.

## Built-in: LocalBackend

Serves files from a local directory tree.

```go
backend, err := vfs.NewLocalBackend("/path/to/root")
```

- Paths are resolved relative to the root directory with `/` as separator.
- Creates use the disposition semantics: `Supersede`, `Create`, `Open`, `OpenIf`, `Overwrite`, `OverwriteIf`.
- Directories are opened with `O_RDONLY` (Linux forbids `O_RDWR` on directories).
- `Enumerate` uses `os.ReadDir` with `filepath.Match` pattern filtering.
- `Remove` delegates to `os.Remove`.

## Custom backend example: in-memory

```go
type MemBackend struct {
    files map[string]*MemFile
}

type MemFile struct {
    data    []byte
    info    vfs.FileInfo
}

func (b *MemBackend) Open(ctx context.Context, opts vfs.OpenOptions) (vfs.Handle, error) {
    f, ok := b.files[opts.Path]
    if !ok {
        if opts.Disposition == vfs.DispositionCreate {
            f = &MemFile{data: []byte{}, info: vfs.FileInfo{
                Name: filepath.Base(opts.Path),
            }}
            b.files[opts.Path] = f
        } else {
            return nil, os.ErrNotExist
        }
    }
    return &MemHandle{file: f, path: opts.Path}, nil
}

type MemHandle struct {
    file   *MemFile
    path   string
    offset int64
}

func (h *MemHandle) Read(ctx context.Context, offset int64, p []byte) (int, error) {
    if offset >= int64(len(h.file.data)) { return 0, io.EOF }
    return copy(p, h.file.data[offset:]), nil
}

func (h *MemHandle) Write(ctx context.Context, offset int64, p []byte) (int, error) {
    // Extend and write
    if int(offset)+len(p) > len(h.file.data) {
        h.file.data = append(h.file.data, make([]byte, int(offset)+len(p)-len(h.file.data))...)
    }
    return copy(h.file.data[offset:], p), nil
}

func (h *MemHandle) Close(ctx context.Context) error { return nil }
func (h *MemHandle) Stat(ctx context.Context) (vfs.FileInfo, error) { return h.file.info, nil }

func (h *MemHandle) Enumerate(ctx context.Context, pattern string) iter.Seq2[vfs.FileInfo, error] {
    // not implemented for individual files
    return func(yield func(vfs.FileInfo, error) bool) {}
}
```

## Enumerate with iter.Seq2

Go 1.23+ range-over-func iterators enable incremental enumeration:

```go
func (h *myHandle) Enumerate(ctx context.Context, pattern string) iter.Seq2[vfs.FileInfo, error] {
    return func(yield func(vfs.FileInfo, error) bool) {
        for _, entry := range h.entries {
            matched, _ := filepath.Match(pattern, entry.Name)
            if !matched { continue }
            if !yield(entry, nil) { return } // caller stopped
        }
    }
}
```

The server calls `yield` repeatedly, encoding each entry into the QUERY_DIRECTORY response until the buffer is full or the iterator is exhausted. Errors from `yield` stop enumeration. The `STATUS_NO_MORE_FILES` response is sent when the iterator finishes.
