package core

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrRefreshTokenNotFound indicates the refresh token was not found in storage
	ErrRefreshTokenNotFound = errors.New("refresh token not found")

	// ErrRefreshTokenExpired indicates the refresh token has expired
	ErrRefreshTokenExpired = errors.New("refresh token expired")
)

// TokenStore defines the interface for storing and retrieving refresh tokens
type TokenStore interface {
	// Set stores a refresh token with associated user data and expiration
	Set(ctx context.Context, token string, userData any, expiry time.Time) error

	// Get retrieves user data associated with a refresh token
	Get(ctx context.Context, token string) (any, error)

	// Delete removes a refresh token from storage
	Delete(ctx context.Context, token string) error

	// Cleanup removes expired tokens
	Cleanup(ctx context.Context) (int, error)

	// Count returns the total number of active refresh tokens
	Count(ctx context.Context) (int, error)
}

// RefreshTokenManager is the higher-level refresh-token lifecycle abstraction.
//
// Unlike TokenStore, it owns the full middleware-facing refresh flow:
// initial persistence on login, lookup during refresh, atomic rotation, and
// logout revocation for the presented token. Implementations may keep all logic
// in a shared datastore and are free to manage successor chains or session
// metadata without exposing those details to the middleware.
//
// ToukaJWTMiddleware uses this interface preferentially when configured. When
// it is nil, the middleware adapts the legacy TokenStore/
// RefreshTokenRotator/RefreshTokenRevoker interfaces to preserve existing
// behavior.
type RefreshTokenManager interface {
	Store(ctx context.Context, token string, userData any, expiry time.Time) error
	Lookup(ctx context.Context, token string) (any, error)
	Rotate(ctx context.Context, oldToken, newToken string, userData any, expiry time.Time) error
	Revoke(ctx context.Context, token string) error
}

// RefreshTokenRotator atomically swaps an old refresh token for a new one.
// Stores that implement this can avoid inconsistent intermediate states during
// refresh-token rotation.
type RefreshTokenRotator interface {
	TokenStore
	Rotate(ctx context.Context, oldToken, newToken string, userData any, expiry time.Time) error
}

// RefreshTokenRevoker atomically revokes one or more refresh tokens.
// Stores that implement this can avoid partial logout state when a logout
// request needs to invalidate a known successor chain.
//
// Revoke must apply to the full batch atomically: on success, every token in
// the provided slice is no longer usable. Implementations should also keep the
// operation idempotent for logout semantics. If Revoke returns
// ErrRefreshTokenNotFound or ErrRefreshTokenExpired, callers assume every token
// in the batch is already absent or unusable and may clear any in-memory logout
// bookkeeping for the whole chain.
type RefreshTokenRevoker interface {
	TokenStore
	Revoke(ctx context.Context, tokens []string) error
}

// RefreshTokenData holds the data stored with each refresh token
type RefreshTokenData struct {
	UserData any       `json:"user_data"`
	Expiry   time.Time `json:"expiry"`
	Created  time.Time `json:"created"`
}

// RefreshTokenState stores refresh-token lifecycle metadata that may need to
// survive custom TokenStore serialization.
type RefreshTokenState struct {
	UserData        any       `json:"user_data"`
	MaxRefreshUntil time.Time `json:"max_refresh_until,omitempty"`
}

// IsExpired checks if the token data has expired
func (r *RefreshTokenData) IsExpired() bool {
	return !time.Now().Before(r.Expiry)
}

// Token represents a complete JWT token pair with metadata
type Token struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	ExpiresAt        int64  `json:"expires_at"`
	CreatedAt        int64  `json:"created_at"`
	RefreshExpiresAt int64  `json:"refresh_expires_at,omitempty"`
}

// ExpiresIn returns the number of seconds until the access token expires
func (t *Token) ExpiresIn() int64 {
	return t.ExpiresAt - time.Now().Unix()
}
