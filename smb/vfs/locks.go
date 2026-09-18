package vfs

// Byte-range locking is delegated to the host application, so locks taken
// over SMB can live in the same table as locks taken over other protocols.
// A server without a locker uses an in-memory one of its own.

// LockOwner identifies who holds a lock. Requests with equal owners come from
// the same holder and never conflict with each other. In SMB a lock belongs
// to the open file handle that took it, so Client identifies the session and
// ID the handle.
type LockOwner struct {
	Client string
	ID     string
}

// LockRange is the byte range [Start, End). End is math.MaxUint64 for a lock
// that extends to the end of the file.
type LockRange struct {
	Start, End uint64
	Exclusive  bool
}

// LockConflict is a lock held by someone else that prevented a request.
type LockConflict struct {
	LockRange
	Owner LockOwner
}

// ByteRangeLocker records advisory byte-range locks. Implementations are safe
// for concurrent use.
type ByteRangeLocker interface {
	// Lock grants r to owner, or returns the conflicting lock and grants
	// nothing. An error other than a conflict fails the request.
	Lock(owner LockOwner, path string, r LockRange) (*LockConflict, error)
	// Unlock releases r from owner's locks on path.
	Unlock(owner LockOwner, path string, r LockRange) error
	// ReleaseOwner drops every lock an owner holds, as when its handle
	// closes.
	ReleaseOwner(owner LockOwner)
	// ReleaseClient drops every lock a client holds, as when its session
	// ends or its connection drops.
	ReleaseClient(client string)
}
