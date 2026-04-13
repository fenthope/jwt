package store

import (
	"github.com/fenthope/jwt/core"
)

type RefreshTokenStorer = core.TokenStore
type RefreshTokenManager = core.RefreshTokenManager
type RefreshTokenData = core.RefreshTokenData

var (
	ErrRefreshTokenNotFound = core.ErrRefreshTokenNotFound
	ErrRefreshTokenExpired  = core.ErrRefreshTokenExpired
)
