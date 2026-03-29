package store

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/fenthope/jwt/core"
)

var _ core.TokenStore = &InMemoryRefreshTokenStore{}

type InMemoryRefreshTokenStore struct {
	tokens map[string]*core.RefreshTokenData
	mu     sync.RWMutex
}

func NewInMemoryRefreshTokenStore() *InMemoryRefreshTokenStore {
	return &InMemoryRefreshTokenStore{
		tokens: make(map[string]*core.RefreshTokenData),
	}
}

func (s *InMemoryRefreshTokenStore) Set(ctx context.Context, token string, userData any, expiry time.Time) error {
	if token == "" {
		return errors.New("token cannot be empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token] = &core.RefreshTokenData{
		UserData: userData,
		Expiry:   expiry,
		Created:  time.Now(),
	}
	return nil
}

func (s *InMemoryRefreshTokenStore) Get(ctx context.Context, token string) (any, error) {
	if token == "" {
		return nil, core.ErrRefreshTokenNotFound
	}
	s.mu.RLock()
	data, exists := s.tokens[token]
	s.mu.RUnlock()
	if !exists {
		return nil, core.ErrRefreshTokenNotFound
	}
	if data.IsExpired() {
		s.mu.Lock()
		// Double-check after acquiring write lock
		if data, exists := s.tokens[token]; exists && data.IsExpired() {
			delete(s.tokens, token)
			s.mu.Unlock()
			return nil, core.ErrRefreshTokenExpired
		}
		s.mu.Unlock()
		// Token was already deleted or refreshed by another goroutine
		return nil, core.ErrRefreshTokenNotFound
	}
	return data.UserData, nil
}

func (s *InMemoryRefreshTokenStore) Delete(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, token)
	return nil
}

func (s *InMemoryRefreshTokenStore) Cleanup(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var cleaned int
	now := time.Now()
	for token, data := range s.tokens {
		if now.After(data.Expiry) {
			delete(s.tokens, token)
			cleaned++
		}
	}
	return cleaned, nil
}

func (s *InMemoryRefreshTokenStore) Count(ctx context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tokens), nil
}

func (s *InMemoryRefreshTokenStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens = make(map[string]*core.RefreshTokenData)
}
