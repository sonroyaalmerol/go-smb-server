package server

import (
	"context"
	"io/fs"
	"iter"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sonroyaalmerol/go-smb-server/smb/vfs"
)

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
	return &memBackend{root: &memNode{name: "", isDir: true, children: map[string]*memNode{}, modTime: time.Now()}}
}

func (b *memBackend) Open(_ context.Context, opts vfs.OpenOptions) (vfs.Handle, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	clean := path.Clean("/" + opts.Path)
	if clean == "/" {
		return &memHandle{n: b.root, b: b}, nil
	}
	dir, base := splitDir(clean)
	parent := b.mustDir(dir)
	if opts.CreateDir {
		if _, ok := parent.children[base]; !ok {
			parent.children[base] = &memNode{name: base, isDir: true, children: map[string]*memNode{}, modTime: time.Now()}
		}
		return &memHandle{n: parent.children[base], b: b}, nil
	}
	switch opts.Disposition {
	case vfs.DispositionCreate:
		if _, ok := parent.children[base]; ok {
			return nil, fs.ErrExist
		}
		parent.children[base] = &memNode{name: base, data: []byte{}, modTime: time.Now()}
		return &memHandle{n: parent.children[base], b: b}, nil
	default:
		n, ok := parent.children[base]
		if !ok {
			if opts.Disposition == vfs.DispositionOpenIf || opts.Disposition == vfs.DispositionOverwriteIf {
				parent.children[base] = &memNode{name: base, data: []byte{}, modTime: time.Now()}
				return &memHandle{n: parent.children[base], b: b}, nil
			}
			return nil, fs.ErrNotExist
		}
		return &memHandle{n: n, b: b}, nil
	}
}

func splitDir(clean string) (dir, base string) {
	if clean == "/" || clean == "" {
		return "", ""
	}
	if i := strings.LastIndex(clean, "/"); i >= 0 {
		return clean[:i], clean[i+1:]
	}
	return "", clean
}

func (b *memBackend) mustDir(p string) *memNode {
	if p == "" {
		return b.root
	}
	n := b.root
	for part := range strings.SplitSeq(strings.TrimPrefix(p, "/"), "/") {
		c, ok := n.children[part]
		if !ok {
			c = &memNode{name: part, isDir: true, children: map[string]*memNode{}, modTime: time.Now()}
			n.children[part] = c
		}
		n = c
	}
	return n
}

type memHandle struct {
	n *memNode
	b *memBackend
}

func (h *memHandle) Read(_ context.Context, offset int64, p []byte) (int, error) {
	h.b.mu.Lock()
	defer h.b.mu.Unlock()
	if offset >= int64(len(h.n.data)) {
		return 0, errEOF
	}
	n := copy(p, h.n.data[offset:])
	return n, nil
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
	star := -1
	mark := 0
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
