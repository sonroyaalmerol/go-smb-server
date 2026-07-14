package main

import (
	"context"
	"flag"
	"io/fs"
	"iter"
	"log/slog"
	"os/signal"
	"path"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sonroyaalmerol/go-smb-server/smb/ntlmssp"
	"github.com/sonroyaalmerol/go-smb-server/smb/server"
	"github.com/sonroyaalmerol/go-smb-server/smb/vfs"
)

func main() {
	addr := flag.String("addr", ":445", "listen address")
	flag.Parse()

	backend := newMemBackend()

	creds := ntlmssp.NewMemoryCredentials()
	creds.Add("", "guest", "")
	creds.Add("WORKGROUP", "guest", "")

	srv, err := server.New(
		server.WithAddr(*addr),
		server.WithShares(vfs.NewDiskShare("share", backend)),
		server.WithAuth(ntlmssp.NewServer(creds, "FILESRV")),
		server.WithLogger(slog.Default()),
	)
	if err != nil {
		slog.Error("new server", "err", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	slog.Info("serving (in-memory backend)", "addr", *addr)
	if err := srv.ListenAndServe(ctx); err != nil {
		slog.Error("serve", "err", err)
	}
}

type memBackend struct {
	mu   sync.Mutex
	root *memNode
}

type memNode struct {
	name     string
	isDir    bool
	data     []byte
	children map[string]*memNode
	modTime  time.Time
}

func newMemBackend() *memBackend {
	return &memBackend{
		root: &memNode{name: "", isDir: true, children: map[string]*memNode{}, modTime: time.Now()},
	}
}

func (b *memBackend) resolve(clean string) *memNode {
	if clean == "/" || clean == "" {
		return b.root
	}
	n := b.root
	for part := range strings.SplitSeq(strings.Trim(clean, "/"), "/") {
		c, ok := n.children[part]
		if !ok {
			return nil
		}
		n = c
	}
	return n
}

func (b *memBackend) parent(clean string) (*memNode, string) {
	dir, base := path.Split(clean)
	n := b.resolve("/" + strings.TrimSuffix(dir, "/"))
	if n == nil {
		return nil, base
	}
	return n, base
}

func (b *memBackend) Remove(_ context.Context, p string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	parent, base := b.parent(path.Clean("/" + p))
	if parent == nil {
		return fs.ErrNotExist
	}
	if _, ok := parent.children[base]; !ok {
		return fs.ErrNotExist
	}
	delete(parent.children, base)
	return nil
}

func (b *memBackend) Open(_ context.Context, opts vfs.OpenOptions) (vfs.Handle, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	clean := path.Clean("/" + opts.Path)
	n := b.resolve(clean)

	if opts.CreateDir {
		if n == nil {
			parent, base := b.parent(clean)
			if parent == nil {
				return nil, fs.ErrNotExist
			}
			n = &memNode{name: base, isDir: true, children: map[string]*memNode{}, modTime: time.Now()}
			parent.children[base] = n
		}
		return &memHandle{n: n, b: b}, nil
	}

	switch opts.Disposition {
	case vfs.DispositionCreate:
		if n != nil {
			return nil, fs.ErrExist
		}
		parent, base := b.parent(clean)
		if parent == nil {
			return nil, fs.ErrNotExist
		}
		n = &memNode{name: base, data: []byte{}, modTime: time.Now()}
		parent.children[base] = n
	case vfs.DispositionOpen:
		if n == nil {
			return nil, fs.ErrNotExist
		}
	case vfs.DispositionOpenIf:
		if n == nil {
			parent, base := b.parent(clean)
			if parent == nil {
				return nil, fs.ErrNotExist
			}
			n = &memNode{name: base, data: []byte{}, modTime: time.Now()}
			parent.children[base] = n
		}
	case vfs.DispositionSupersede, vfs.DispositionOverwrite, vfs.DispositionOverwriteIf:
		if n == nil {
			parent, base := b.parent(clean)
			if parent == nil {
				return nil, fs.ErrNotExist
			}
			n = &memNode{name: base, data: []byte{}, modTime: time.Now()}
			parent.children[base] = n
		} else {
			n.data = n.data[:0]
		}
	default:
		if n == nil {
			return nil, fs.ErrNotExist
		}
	}
	return &memHandle{n: n, b: b}, nil
}

type memHandle struct {
	n *memNode
	b *memBackend
}

func (h *memHandle) Read(_ context.Context, offset int64, p []byte) (int, error) {
	h.b.mu.Lock()
	defer h.b.mu.Unlock()
	if offset >= int64(len(h.n.data)) {
		return 0, nil
	}
	return copy(p, h.n.data[offset:]), nil
}

func (h *memHandle) Write(_ context.Context, offset int64, p []byte) (int, error) {
	h.b.mu.Lock()
	defer h.b.mu.Unlock()
	end := int(offset) + len(p)
	if end > len(h.n.data) {
		grow := make([]byte, end-len(h.n.data))
		h.n.data = append(h.n.data, grow...)
	}
	copy(h.n.data[offset:], p)
	h.n.modTime = time.Now()
	return len(p), nil
}

func (h *memHandle) Close(_ context.Context) error { return nil }

func (h *memHandle) SetInfo(_ context.Context, req *vfs.SetInfoRequest) error {
	h.b.mu.Lock()
	defer h.b.mu.Unlock()
	if req.EndOfFile != nil {
		sz := int(*req.EndOfFile)
		if sz < len(h.n.data) {
			h.n.data = h.n.data[:sz]
		}
	}
	if req.LastWriteTime != nil {
		h.n.modTime = *req.LastWriteTime
	}
	return nil
}

func (h *memHandle) Rename(_ context.Context, newPath string, _ bool) error {
	h.b.mu.Lock()
	defer h.b.mu.Unlock()
	clean := path.Clean("/" + newPath)
	parent, base := h.b.parent(clean)
	if parent == nil {
		return fs.ErrNotExist
	}
	oldParent, oldBase := h.b.parent(path.Clean("/" + h.n.name))
	if oldParent != nil {
		delete(oldParent.children, oldBase)
	}
	h.n.name = base
	parent.children[base] = h.n
	return nil
}

func (h *memHandle) Stat(_ context.Context) (vfs.FileInfo, error) {
	h.b.mu.Lock()
	defer h.b.mu.Unlock()
	return vfs.FileInfo{
		Name:         h.n.name,
		Size:         int64(len(h.n.data)),
		IsDir:        h.n.isDir,
		CreationTime: h.n.modTime,
		LastAccess:   h.n.modTime,
		LastWrite:    h.n.modTime,
		ChangeTime:   h.n.modTime,
	}, nil
}

func (h *memHandle) Enumerate(_ context.Context, pattern string) iter.Seq2[vfs.FileInfo, error] {
	return func(yield func(vfs.FileInfo, error) bool) {
		h.b.mu.Lock()
		defer h.b.mu.Unlock()
		names := make([]string, 0, len(h.n.children))
		for name := range h.n.children {
			if pattern == "" || pattern == "*" || matchGlob(pattern, name) {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		for _, name := range names {
			c := h.n.children[name]
			if !yield(vfs.FileInfo{
				Name:         c.name,
				Size:         int64(len(c.data)),
				IsDir:        c.isDir,
				CreationTime: c.modTime,
				LastAccess:   c.modTime,
				LastWrite:    c.modTime,
				ChangeTime:   c.modTime,
			}, nil) {
				return
			}
		}
	}
}

func matchGlob(pattern, name string) bool {
	pi, ni := 0, 0
	star, mark := -1, 0
	for ni < len(name) {
		if pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == name[ni]) {
			pi++
			ni++
		} else if pi < len(pattern) && pattern[pi] == '*' {
			star = pi
			mark = ni
			pi++
		} else if star != -1 {
			pi = star + 1
			mark++
			ni = mark
		} else {
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}
