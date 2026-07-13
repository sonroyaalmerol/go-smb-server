package vfs

import (
	"context"
	"fmt"
	"io/fs"
	"iter"
	"os"
	"path"
	"path/filepath"
	"time"
)

type Share interface {
	Name() string
	Backend() Backend
}

type DiskShare struct {
	name    string
	backend Backend
}

func NewDiskShare(name string, backend Backend) DiskShare {
	return DiskShare{name: name, backend: backend}
}

func (s DiskShare) Name() string { return s.name }

func (s DiskShare) Backend() Backend { return s.backend }

const (
	DispositionSupersede   uint32 = 0x00000000
	DispositionOpen        uint32 = 0x00000001
	DispositionCreate      uint32 = 0x00000002
	DispositionOpenIf      uint32 = 0x00000003
	DispositionOverwrite   uint32 = 0x00000004
	DispositionOverwriteIf uint32 = 0x00000005
)

type OpenOptions struct {
	Path        string
	Disposition uint32
	CreateDir   bool
	Append      bool
}

type FileInfo struct {
	Name         string
	Size         int64
	IsDir        bool
	Attributes   uint32
	CreationTime time.Time
	LastAccess   time.Time
	LastWrite    time.Time
	ChangeTime   time.Time
}

type Handle interface {
	Read(ctx context.Context, offset int64, p []byte) (int, error)
	Write(ctx context.Context, offset int64, p []byte) (int, error)
	Close(ctx context.Context) error
	Stat(ctx context.Context) (FileInfo, error)
	Enumerate(ctx context.Context, pattern string) iter.Seq2[FileInfo, error]
}

type Backend interface {
	Open(ctx context.Context, opts OpenOptions) (Handle, error)
}

type Remover interface {
	Remove(ctx context.Context, path string) error
}

type LocalBackend struct {
	Root string
}

func NewLocalBackend(root string) (*LocalBackend, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	return &LocalBackend{Root: abs}, nil
}

func (b *LocalBackend) Remove(_ context.Context, p string) error {
	clean := path.Clean("/" + p)
	if clean == "/" {
		clean = ""
	}
	full := filepath.Join(b.Root, filepath.FromSlash(clean))
	return os.RemoveAll(full)
}

func (b *LocalBackend) Open(_ context.Context, opts OpenOptions) (Handle, error) {
	clean := path.Clean("/" + opts.Path)
	if clean == "/" {
		clean = ""
	}
	full := filepath.Join(b.Root, filepath.FromSlash(clean))
	if full == b.Root {
		full = filepath.Join(b.Root, ".")
	}

	flags := getFlags(opts.Disposition, opts.Append)
	if opts.CreateDir {
		if err := os.Mkdir(full, 0o755); err != nil && !os.IsExist(err) {
			return nil, err
		}
	}
	f, err := os.OpenFile(full, flags, 0o644)
	if err != nil {
		return nil, err
	}
	return &localHandle{f: f, name: filepath.Base(full)}, nil
}

func getFlags(disp uint32, appendFile bool) int {
	switch disp {
	case DispositionCreate:
		return os.O_CREATE | os.O_EXCL
	case DispositionSupersede:
		return os.O_CREATE | os.O_TRUNC
	case DispositionOverwrite, DispositionOverwriteIf:
		return os.O_CREATE | os.O_TRUNC | os.O_RDWR
	default:
		if appendFile {
			return os.O_APPEND | os.O_CREATE | os.O_RDWR
		}
		return os.O_RDWR
	}
}

type localHandle struct {
	f    *os.File
	name string
}

func (h *localHandle) Read(_ context.Context, offset int64, p []byte) (int, error) {
	return h.f.ReadAt(p, offset)
}

func (h *localHandle) Write(_ context.Context, offset int64, p []byte) (int, error) {
	return h.f.WriteAt(p, offset)
}

func (h *localHandle) Close(_ context.Context) error { return h.f.Close() }

func (h *localHandle) Stat(_ context.Context) (FileInfo, error) {
	fi, err := h.f.Stat()
	if err != nil {
		return FileInfo{}, err
	}
	return statToFileInfo(h.name, fi), nil
}

func (h *localHandle) Enumerate(_ context.Context, pattern string) iter.Seq2[FileInfo, error] {
	return func(yield func(FileInfo, error) bool) {
		entries, err := os.ReadDir(h.f.Name())
		if err != nil {
			yield(FileInfo{}, err)
			return
		}
		for _, e := range entries {
			if pattern != "" {
				matched, err := filepath.Match(pattern, e.Name())
				if err != nil {
					yield(FileInfo{}, fmt.Errorf("vfs: bad search pattern %q: %w", pattern, err))
					return
				}
				if !matched {
					continue
				}
			}
			fi, err := e.Info()
			if err != nil {
				continue
			}
			if !yield(statToFileInfo(e.Name(), fi), nil) {
				return
			}
		}
	}
}

func statToFileInfo(name string, fi fs.FileInfo) FileInfo {
	now := time.Now()
	return FileInfo{
		Name:         name,
		Size:         fi.Size(),
		IsDir:        fi.IsDir(),
		CreationTime: fi.ModTime(),
		LastAccess:   fi.ModTime(),
		LastWrite:    fi.ModTime(),
		ChangeTime:   now,
	}
}
