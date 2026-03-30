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

func (s *InMemoryRefreshTokenStore) cleanupExpiredLocked(now time.Time) int {
	var cleaned int
	for token, data := range s.tokens {
		if now.After(data.Expiry) {
			delete(s.tokens, token)
			cleaned++
		}
	}
	return cleaned
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
	s.cleanupExpiredLocked(time.Now())
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
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupExpiredLocked(time.Now())
	data, exists := s.tokens[token]
	if !exists {
		return nil, core.ErrRefreshTokenNotFound
	}
	if data.IsExpired() {
		delete(s.tokens, token)
		return nil, core.ErrRefreshTokenExpired
	}
	return data.UserData, nil
}

func (s *InMemoryRefreshTokenStore) Consume(ctx context.Context, token string) (any, error) {
	if token == "" {
		return nil, core.ErrRefreshTokenNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupExpiredLocked(time.Now())
	data, exists := s.tokens[token]
	if !exists {
		return nil, core.ErrRefreshTokenNotFound
	}
	if data.IsExpired() {
		delete(s.tokens, token)
		return nil, core.ErrRefreshTokenExpired
	}
	delete(s.tokens, token)
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
	s.cleanupExpiredLocked(now)
	data, exists := s.tokens[oldToken]
	if !exists {
		return core.ErrRefreshTokenNotFound
	}
	if data.IsExpired() {
		delete(s.tokens, oldToken)
		return core.ErrRefreshTokenExpired
	}
	s.tokens[newToken] = &core.RefreshTokenData{
		UserData: userData,
		Expiry:   expiry,
		Created:  now,
	}
	delete(s.tokens, oldToken)
	return nil
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
	return s.cleanupExpiredLocked(time.Now()), nil
}

func (s *InMemoryRefreshTokenStore) Count(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupExpiredLocked(time.Now())
	return len(s.tokens), nil
}

func (s *InMemoryRefreshTokenStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens = make(map[string]*core.RefreshTokenData)
}
