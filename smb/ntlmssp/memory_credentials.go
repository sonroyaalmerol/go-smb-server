package ntlmssp

import (
	"context"
	"sync"
)

type MemoryCredentials struct {
	mu   sync.RWMutex
	keys map[string][]byte
}

func NewMemoryCredentials() *MemoryCredentials {
	return &MemoryCredentials{keys: make(map[string][]byte)}
}

func (m *MemoryCredentials) Add(domain, user, password string) {
	key := NTOWFv2(password, user, domain)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[domain+"\\"+user] = key
}

func (m *MemoryCredentials) AddKey(domain, user string, key []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(key))
	copy(cp, key)
	m.keys[domain+"\\"+user] = cp
}

func (m *MemoryCredentials) LookupNTOWFv2(_ context.Context, domain, user string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if k, ok := m.keys[domain+"\\"+user]; ok {
		return k, nil
	}
	return nil, ErrUnknownUser
}
