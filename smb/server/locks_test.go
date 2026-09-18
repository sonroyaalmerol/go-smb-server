package server

import (
	"math"
	"testing"

	"github.com/sonroyaalmerol/go-smb-server/smb/vfs"
)

func TestLockRangeConversion(t *testing.T) {
	tests := []struct {
		name         string
		offset, size uint64
		wantStart    uint64
		wantEnd      uint64
	}{
		{name: "a plain range", offset: 10, size: 90, wantStart: 10, wantEnd: 100},
		{name: "zero length covers nothing", offset: 10, size: 0, wantStart: 10, wantEnd: 10},
		{name: "a length past the address space runs to the end of the file",
			offset: 100, size: math.MaxUint64, wantStart: 100, wantEnd: math.MaxUint64},
		{name: "the whole file", offset: 0, size: math.MaxUint64, wantStart: 0, wantEnd: math.MaxUint64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := lockRange(tt.offset, tt.size, true)
			if r.Start != tt.wantStart || r.End != tt.wantEnd {
				t.Fatalf("lockRange(%d, %d) = [%d, %d), want [%d, %d)",
					tt.offset, tt.size, r.Start, r.End, tt.wantStart, tt.wantEnd)
			}
			if !r.Exclusive {
				t.Fatal("lockRange() dropped the exclusive flag")
			}
		})
	}
}

// Locks belong to the handle that took them, so a holder never conflicts with
// itself and closing a handle frees what it held.
func TestMemLockerTracksOwners(t *testing.T) {
	locker := newMemLocker()
	first := vfs.LockOwner{Client: "smb/1", ID: "handle-1"}
	second := vfs.LockOwner{Client: "smb/1", ID: "handle-2"}
	other := vfs.LockOwner{Client: "smb/2", ID: "handle-3"}
	exclusive := vfs.LockRange{Start: 0, End: 100, Exclusive: true}

	if conflict, err := locker.Lock(first, "/f", exclusive); err != nil || conflict != nil {
		t.Fatalf("Lock() = %v, %v; want it granted", conflict, err)
	}
	// The same owner may lock overlapping bytes again.
	if conflict, err := locker.Lock(first, "/f", vfs.LockRange{Start: 50, End: 60, Exclusive: true}); err != nil || conflict != nil {
		t.Fatalf("Lock() by the same owner = %v, %v; want it granted", conflict, err)
	}
	// Another handle does not.
	conflict, err := locker.Lock(second, "/f", exclusive)
	if err != nil {
		t.Fatalf("Lock(second) error = %v", err)
	}
	if conflict == nil || conflict.Owner != first {
		t.Fatalf("Lock(second) conflict = %v, want the first handle's lock", conflict)
	}

	// Unlocking is owner-scoped: another owner cannot drop a lock it does not
	// hold.
	if err := locker.Unlock(other, "/f", exclusive); err != nil {
		t.Fatalf("Unlock(other) error = %v", err)
	}
	if conflict, _ := locker.Lock(second, "/f", exclusive); conflict == nil {
		t.Fatal("another owner's unlock released the lock")
	}

	locker.ReleaseOwner(first)
	if conflict, err := locker.Lock(second, "/f", exclusive); err != nil || conflict != nil {
		t.Fatalf("Lock() after the holder closed = %v, %v; want it granted", conflict, err)
	}

	locker.ReleaseClient("smb/1")
	if conflict, err := locker.Lock(other, "/f", exclusive); err != nil || conflict != nil {
		t.Fatalf("Lock() after the session ended = %v, %v; want it granted", conflict, err)
	}
}

func TestMemLockerSharedLocksCoexist(t *testing.T) {
	locker := newMemLocker()
	shared := vfs.LockRange{Start: 0, End: 100}

	for _, id := range []string{"handle-1", "handle-2", "handle-3"} {
		owner := vfs.LockOwner{Client: "smb/1", ID: id}
		if conflict, err := locker.Lock(owner, "/f", shared); err != nil || conflict != nil {
			t.Fatalf("shared Lock(%s) = %v, %v; want it granted", id, conflict, err)
		}
	}
	conflict, err := locker.Lock(vfs.LockOwner{Client: "smb/2", ID: "writer"}, "/f",
		vfs.LockRange{Start: 10, End: 20, Exclusive: true})
	if err != nil {
		t.Fatalf("exclusive Lock() error = %v", err)
	}
	if conflict == nil {
		t.Fatal("an exclusive lock was granted over shared-locked bytes")
	}
}
