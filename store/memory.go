package store

import (
	"container/heap"
	"context"
	"errors"
	"sync"
	"time"

	"github.com/fenthope/jwt/core"
)

var _ core.TokenStore = &InMemoryRefreshTokenStore{}

type expiryEntry struct {
	token  string
	expiry time.Time
	index  int
}

type expiryHeap []*expiryEntry

func (h expiryHeap) Len() int { return len(h) }

func (h expiryHeap) Less(i, j int) bool {
	return h[i].expiry.Before(h[j].expiry)
}

func (h expiryHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *expiryHeap) Push(x any) {
	entry := x.(*expiryEntry)
	entry.index = len(*h)
	*h = append(*h, entry)
}

func (h *expiryHeap) Pop() any {
	old := *h
	n := len(old)
	entry := old[n-1]
	old[n-1] = nil
	entry.index = -1
	*h = old[:n-1]
	return entry
}

type InMemoryRefreshTokenStore struct {
	tokens   map[string]*core.RefreshTokenData
	expiryIx map[string]*expiryEntry
	expiries expiryHeap
	mu       sync.RWMutex
}

func NewInMemoryRefreshTokenStore() *InMemoryRefreshTokenStore {
	s := &InMemoryRefreshTokenStore{
		tokens:   make(map[string]*core.RefreshTokenData),
		expiryIx: make(map[string]*expiryEntry),
	}
	heap.Init(&s.expiries)
	return s
}

func (s *InMemoryRefreshTokenStore) purgeExpiredLocked(now time.Time) int {
	var cleaned int
	for s.expiries.Len() > 0 {
		entry := s.expiries[0]
		if entry.expiry.After(now) {
			break
		}
		heap.Pop(&s.expiries)
		current, exists := s.expiryIx[entry.token]
		if !exists || current != entry {
			continue
		}
		delete(s.expiryIx, entry.token)
		delete(s.tokens, entry.token)
		cleaned++
	}
	return cleaned
}

func (s *InMemoryRefreshTokenStore) setLocked(token string, userData any, expiry, created time.Time) {
	if existing, exists := s.expiryIx[token]; exists {
		heap.Remove(&s.expiries, existing.index)
		delete(s.expiryIx, token)
	}
	entry := &expiryEntry{token: token, expiry: expiry}
	heap.Push(&s.expiries, entry)
	s.expiryIx[token] = entry
	s.tokens[token] = &core.RefreshTokenData{
		UserData: userData,
		Expiry:   expiry,
		Created:  created,
	}
}

func (s *InMemoryRefreshTokenStore) deleteLocked(token string) {
	if entry, exists := s.expiryIx[token]; exists {
		heap.Remove(&s.expiries, entry.index)
		delete(s.expiryIx, token)
	}
	delete(s.tokens, token)
}

func (s *InMemoryRefreshTokenStore) Set(ctx context.Context, token string, userData any, expiry time.Time) error {
	if token == "" {
		return errors.New("token cannot be empty")
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked(now)
	s.setLocked(token, userData, expiry, now)
	return nil
}

func (s *InMemoryRefreshTokenStore) Get(ctx context.Context, token string) (any, error) {
	if token == "" {
		return nil, core.ErrRefreshTokenNotFound
	}
	now := time.Now()
	s.mu.RLock()
	data, exists := s.tokens[token]
	if !exists {
		s.mu.RUnlock()
		return nil, core.ErrRefreshTokenNotFound
	}
	if !now.After(data.Expiry) {
		userData := data.UserData
		s.mu.RUnlock()
		return userData, nil
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked(now)
	data, exists = s.tokens[token]
	if !exists {
		return nil, core.ErrRefreshTokenExpired
	}
	if now.After(data.Expiry) {
		s.deleteLocked(token)
		return nil, core.ErrRefreshTokenExpired
	}
	return data.UserData, nil
}

func (s *InMemoryRefreshTokenStore) Consume(ctx context.Context, token string) (any, error) {
	if token == "" {
		return nil, core.ErrRefreshTokenNotFound
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked(now)
	data, exists := s.tokens[token]
	if !exists {
		return nil, core.ErrRefreshTokenNotFound
	}
	if now.After(data.Expiry) {
		s.deleteLocked(token)
		return nil, core.ErrRefreshTokenExpired
	}
	s.deleteLocked(token)
	return data.UserData, nil
}

func (s *InMemoryRefreshTokenStore) Rotate(ctx context.Context, oldToken, newToken string, userData any, expiry time.Time) error {
	if oldToken == "" {
		return core.ErrRefreshTokenNotFound
	}
	if newToken == "" {
		return errors.New("token cannot be empty")
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked(now)
	data, exists := s.tokens[oldToken]
	if !exists {
		return core.ErrRefreshTokenNotFound
	}
	if now.After(data.Expiry) {
		s.deleteLocked(oldToken)
		return core.ErrRefreshTokenExpired
	}
	s.setLocked(newToken, userData, expiry, now)
	s.deleteLocked(oldToken)
	return nil
}

func (s *InMemoryRefreshTokenStore) Delete(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteLocked(token)
	return nil
}

func (s *InMemoryRefreshTokenStore) Cleanup(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.purgeExpiredLocked(time.Now()), nil
}

func (s *InMemoryRefreshTokenStore) Count(ctx context.Context) (int, error) {
	now := time.Now()
	s.mu.RLock()
	count := len(s.tokens)
	if s.expiries.Len() == 0 || s.expiries[0].expiry.After(now) {
		s.mu.RUnlock()
		return count, nil
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked(now)
	return len(s.tokens), nil
}

func (s *InMemoryRefreshTokenStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens = make(map[string]*core.RefreshTokenData)
	s.expiryIx = make(map[string]*expiryEntry)
	s.expiries = expiryHeap{}
	heap.Init(&s.expiries)
}
