package server

import (
	"math"
	"sync"

	"github.com/sonroyaalmerol/go-smb-server/smb/vfs"
)

// lockToEOF is the range end for a lock that runs to the end of the file.
const lockToEOF = uint64(math.MaxUint64)

// lockTable returns the server's byte-range locker, creating the default one
// for a Server that was built without New.
func (s *Server) lockTable() vfs.ByteRangeLocker {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locker == nil {
		s.locker = newMemLocker()
	}
	return s.locker
}

// memLocker is the byte-range lock table a server uses when the application
// does not supply one. It tracks the owner of every lock, so a handle's locks
// are released when it closes and a holder never conflicts with itself.
type memLocker struct {
	mu    sync.Mutex
	files map[string][]heldLock
}

type heldLock struct {
	vfs.LockRange
	owner vfs.LockOwner
}

func newMemLocker() *memLocker {
	return &memLocker{files: make(map[string][]heldLock)}
}

func (m *memLocker) Lock(owner vfs.LockOwner, path string, r vfs.LockRange) (*vfs.LockConflict, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, held := range m.files[path] {
		if held.owner == owner || !overlaps(held.LockRange, r) {
			continue
		}
		if held.Exclusive || r.Exclusive {
			conflict := vfs.LockConflict{LockRange: held.LockRange, Owner: held.owner}
			return &conflict, nil
		}
	}
	m.files[path] = append(m.files[path], heldLock{LockRange: r, owner: owner})
	return nil, nil
}

func (m *memLocker) Unlock(owner vfs.LockOwner, path string, r vfs.LockRange) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	held := m.files[path]
	for i, lock := range held {
		if lock.owner != owner || lock.Start != r.Start || lock.End != r.End {
			continue
		}
		m.files[path] = append(held[:i], held[i+1:]...)
		if len(m.files[path]) == 0 {
			delete(m.files, path)
		}
		return nil
	}
	return nil
}

func (m *memLocker) ReleaseOwner(owner vfs.LockOwner) {
	m.release(func(l heldLock) bool { return l.owner == owner })
}

func (m *memLocker) ReleaseClient(client string) {
	m.release(func(l heldLock) bool { return l.owner.Client == client })
}

func (m *memLocker) release(match func(heldLock) bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for path, held := range m.files {
		kept := held[:0]
		for _, lock := range held {
			if !match(lock) {
				kept = append(kept, lock)
			}
		}
		if len(kept) == 0 {
			delete(m.files, path)
			continue
		}
		m.files[path] = kept
	}
}

func overlaps(a, b vfs.LockRange) bool {
	return a.Start < b.End && b.Start < a.End
}

// lockRange converts an SMB lock element to a range. A length that runs past
// the end of the address space means "to end of file".
func lockRange(offset, length uint64, exclusive bool) vfs.LockRange {
	end := lockToEOF
	if length < lockToEOF-offset {
		end = offset + length
	}
	return vfs.LockRange{Start: offset, End: end, Exclusive: exclusive}
}

// lockOwner identifies the open that a lock belongs to: in SMB locks are held
// by the file handle, so two handles conflict even within one session.
func lockOwner(sessionID uint64, fileID [16]byte) vfs.LockOwner {
	return vfs.LockOwner{
		Client: "smb/" + formatUint(sessionID),
		ID:     formatFileID(fileID),
	}
}

func formatUint(v uint64) string {
	const digits = "0123456789abcdef"
	if v == 0 {
		return "0"
	}
	var buf [16]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = digits[v&0xF]
		v >>= 4
	}
	return string(buf[i:])
}

func formatFileID(id [16]byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 32)
	for _, b := range id {
		out = append(out, digits[b>>4], digits[b&0xF])
	}
	return string(out)
}
