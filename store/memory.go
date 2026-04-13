package store

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/fenthope/jwt/core"
)

var _ core.TokenStore = &InMemoryRefreshTokenStore{}
var _ core.RefreshTokenRotator = &InMemoryRefreshTokenStore{}
var _ core.RefreshTokenRevoker = &InMemoryRefreshTokenStore{}

type InMemoryRefreshTokenStore struct {
	tokens  map[string]*core.RefreshTokenData
	mu      sync.RWMutex
	nowFunc func() time.Time
}

func NewInMemoryRefreshTokenStore() *InMemoryRefreshTokenStore {
	return &InMemoryRefreshTokenStore{
		tokens:  make(map[string]*core.RefreshTokenData),
		nowFunc: time.Now,
	}
}

func NewInMemoryRefreshTokenStoreWithClock(nowFunc func() time.Time) *InMemoryRefreshTokenStore {
	if nowFunc == nil {
		nowFunc = time.Now
	}
	return &InMemoryRefreshTokenStore{
		tokens:  make(map[string]*core.RefreshTokenData),
		nowFunc: nowFunc,
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
		Created:  s.nowFunc(),
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
	if !s.nowFunc().Before(data.Expiry) {
		s.mu.Lock()
		// Double-check after acquiring write lock
		if data, exists := s.tokens[token]; exists && !s.nowFunc().Before(data.Expiry) {
			delete(s.tokens, token)
			s.mu.Unlock()
			return nil, core.ErrRefreshTokenExpired
		}
		s.mu.Unlock()
		// Token was already deleted or refreshed by another goroutine
		return nil, core.ErrRefreshTokenExpired
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

func (s *InMemoryRefreshTokenStore) Rotate(ctx context.Context, oldToken, newToken string, userData any, expiry time.Time) error {
	if oldToken == "" || newToken == "" {
		return errors.New("token cannot be empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, exists := s.tokens[oldToken]
	if !exists {
		return core.ErrRefreshTokenNotFound
	}
	if !s.nowFunc().Before(data.Expiry) {
		delete(s.tokens, oldToken)
		return core.ErrRefreshTokenExpired
	}
	delete(s.tokens, oldToken)
	s.tokens[newToken] = &core.RefreshTokenData{
		UserData: userData,
		Expiry:   expiry,
		Created:  s.nowFunc(),
	}
	return nil
}

func (s *InMemoryRefreshTokenStore) Revoke(ctx context.Context, tokens []string) error {
	if len(tokens) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, token := range tokens {
		if token == "" {
			continue
		}
		delete(s.tokens, token)
	}
	return nil
}

func (s *InMemoryRefreshTokenStore) Cleanup(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var cleaned int
	now := s.nowFunc()
	for token, data := range s.tokens {
		if !now.Before(data.Expiry) {
			delete(s.tokens, token)
			cleaned++
		}
	}
	return cleaned, nil
}

func (s *InMemoryRefreshTokenStore) Count(ctx context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var count int
	now := s.nowFunc()
	for _, data := range s.tokens {
		if now.Before(data.Expiry) {
			count++
		}
	}
	return count, nil
}

func (s *InMemoryRefreshTokenStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens = make(map[string]*core.RefreshTokenData)
}
