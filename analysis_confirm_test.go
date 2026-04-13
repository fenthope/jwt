package jwt

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/appleboy/gofight/v2"
	"github.com/fenthope/jwt/core"
	"github.com/fenthope/jwt/store"
	"github.com/golang-jwt/jwt/v5"
	"github.com/infinite-iroha/touka"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// These are regression tests for issues that were previously confirmed in the
// implementation. They assert the corrected behavior to prevent reintroduction.

func TestAnalysisConfirmLogoutDoesNotRevokeRefreshToken(t *testing.T) {
	auth, err := New(&ToukaJWTMiddleware{
		Realm: "analysis",
		Key:   testPrivateKey(t),
		Authenticator: func(c *touka.Context) (any, error) {
			return "admin", nil
		},
		PayloadFunc: func(data any) MapClaims {
			return MapClaims{"identity": data}
		},
	})
	require.NoError(t, err)

	handler := toukaHandler(auth)
	r := gofight.New()

	var refreshToken string
	r.POST("/login").Run(handler, func(resp gofight.HTTPResponse, req gofight.HTTPRequest) {
		require.Equal(t, http.StatusOK, resp.Code)
		refreshToken = gjson.Get(resp.Body.String(), "refresh_token").String()
		require.NotEmpty(t, refreshToken)
	})

	r.POST("/logout").SetForm(gofight.H{"refresh_token": refreshToken}).Run(handler, func(resp gofight.HTTPResponse, req gofight.HTTPRequest) {
		require.Equal(t, http.StatusOK, resp.Code)
	})

	r.POST("/refresh").SetForm(gofight.H{"refresh_token": refreshToken}).Run(handler, func(resp gofight.HTTPResponse, req gofight.HTTPRequest) {
		assert.Equal(t, http.StatusUnauthorized, resp.Code)
	})
}

func TestAnalysisConfirmMaxRefreshIsSlidingWindow(t *testing.T) {
	auth, err := New(&ToukaJWTMiddleware{
		Realm:      "analysis",
		Key:        testPrivateKey(t),
		MaxRefresh: 3 * time.Second,
		Authenticator: func(c *touka.Context) (any, error) {
			return "admin", nil
		},
		PayloadFunc: func(data any) MapClaims {
			return MapClaims{"identity": data}
		},
	})
	require.NoError(t, err)

	handler := toukaHandler(auth)
	r := gofight.New()

	var refreshToken string
	r.POST("/login").Run(handler, func(resp gofight.HTTPResponse, req gofight.HTTPRequest) {
		require.Equal(t, http.StatusOK, resp.Code)
		refreshToken = gjson.Get(resp.Body.String(), "refresh_token").String()
		require.NotEmpty(t, refreshToken)
	})

	time.Sleep(100 * time.Millisecond)

	r.POST("/refresh").SetForm(gofight.H{"refresh_token": refreshToken}).Run(handler, func(resp gofight.HTTPResponse, req gofight.HTTPRequest) {
		require.Equal(t, http.StatusOK, resp.Code)
		refreshToken = gjson.Get(resp.Body.String(), "refresh_token").String()
		require.NotEmpty(t, refreshToken)
	})

	time.Sleep(3200 * time.Millisecond)

	r.POST("/refresh").SetForm(gofight.H{"refresh_token": refreshToken}).Run(handler, func(resp gofight.HTTPResponse, req gofight.HTTPRequest) {
		assert.Equal(t, http.StatusUnauthorized, resp.Code)
	})
}

func TestAnalysisConfirmRefreshPreservesMaxRefreshDeadlineInResponseAndCookie(t *testing.T) {
	now := time.Now()
	var loginRefreshExpiresAt int64
	var refreshRefreshExpiresAt int64
	auth, err := New(&ToukaJWTMiddleware{
		Realm:      "analysis",
		Key:        testPrivateKey(t),
		MaxRefresh: 3 * time.Second,
		SendCookie: true,
		TimeFunc: func() time.Time {
			return now
		},
		Authenticator: func(c *touka.Context) (any, error) {
			return "admin", nil
		},
		LoginResponse: func(c *touka.Context, code int, token *core.Token) {
			loginRefreshExpiresAt = token.RefreshExpiresAt
			c.JSON(code, touka.H{
				"code":               code,
				"access_token":       token.AccessToken,
				"refresh_token":      token.RefreshToken,
				"refresh_expires_at": token.RefreshExpiresAt,
			})
		},
		RefreshResponse: func(c *touka.Context, code int, token *core.Token) {
			refreshRefreshExpiresAt = token.RefreshExpiresAt
			c.JSON(code, touka.H{
				"code":               code,
				"access_token":       token.AccessToken,
				"refresh_token":      token.RefreshToken,
				"refresh_expires_at": token.RefreshExpiresAt,
			})
		},
		PayloadFunc: func(data any) MapClaims {
			return MapClaims{"identity": data}
		},
	})
	require.NoError(t, err)

	handler := toukaHandler(auth)
	r := gofight.New()

	var refreshToken string
	loginAt := now
	refreshDeadline := loginAt.Add(auth.MaxRefresh)
	r.POST("/login").Run(handler, func(resp gofight.HTTPResponse, req gofight.HTTPRequest) {
		require.Equal(t, http.StatusOK, resp.Code)
		refreshToken = gjson.Get(resp.Body.String(), "refresh_token").String()
		require.NotEmpty(t, refreshToken)
		assert.Equal(t, refreshDeadline.Unix(), gjson.Get(resp.Body.String(), "refresh_expires_at").Int())
		assert.Equal(t, refreshDeadline.Unix(), loginRefreshExpiresAt)
	})

	now = now.Add(1200 * time.Millisecond)
	expectedRemaining := int(refreshDeadline.Unix() - now.Unix())
	if expectedRemaining < 0 {
		expectedRemaining = 0
	}

	r.POST("/refresh").SetForm(gofight.H{"refresh_token": refreshToken}).Run(handler, func(resp gofight.HTTPResponse, req gofight.HTTPRequest) {
		require.Equal(t, http.StatusOK, resp.Code)
		assert.Equal(t, refreshDeadline.Unix(), gjson.Get(resp.Body.String(), "refresh_expires_at").Int())
		assert.Equal(t, refreshDeadline.Unix(), refreshRefreshExpiresAt)

		cookies := resp.HeaderMap["Set-Cookie"]
		var refreshCookie string
		for _, value := range cookies {
			if strings.Contains(value, auth.RefreshTokenCookieName+"=") {
				refreshCookie = value
				break
			}
		}
		require.NotEmpty(t, refreshCookie)
		assert.Contains(t, refreshCookie, "Max-Age=")
		assert.Contains(t, refreshCookie, "Max-Age="+strconv.Itoa(expectedRemaining))
	})
}

func TestAnalysisConfirmMalformedTokenLookupPanics(t *testing.T) {
	_, err := New(&ToukaJWTMiddleware{
		Realm:       "analysis",
		Key:         testPrivateKey(t),
		TokenLookup: "header",
	})
	assert.ErrorIs(t, err, ErrInvalidTokenLookup)
}

func TestAnalysisConfirmCustomExpFieldEnforcesExpiry(t *testing.T) {
	now := time.Now()
	auth, err := New(&ToukaJWTMiddleware{
		Realm:    "analysis",
		Key:      testPrivateKey(t),
		ExpField: "expires_at",
		TimeFunc: func() time.Time { return now },
		Authenticator: func(c *touka.Context) (any, error) {
			return "admin", nil
		},
		PayloadFunc: func(data any) MapClaims {
			return MapClaims{"identity": data}
		},
	})
	require.NoError(t, err)

	handler := toukaHandler(auth)
	r := gofight.New()

	var accessToken string
	r.POST("/login").Run(handler, func(resp gofight.HTTPResponse, req gofight.HTTPRequest) {
		require.Equal(t, http.StatusOK, resp.Code)
		accessToken = gjson.Get(resp.Body.String(), "access_token").String()
		require.NotEmpty(t, accessToken)
	})

	now = now.Add(auth.Timeout + time.Minute)

	r.GET("/auth/hello").SetHeader(gofight.H{"Authorization": "Bearer " + accessToken}).Run(handler, func(resp gofight.HTTPResponse, req gofight.HTTPRequest) {
		assert.Equal(t, http.StatusUnauthorized, resp.Code)
		assert.Contains(t, resp.Body.String(), ErrExpiredToken.Error())
	})
}

func TestAnalysisConfirmParserUsesMiddlewareTimeFunc(t *testing.T) {
	now := time.Now()
	auth, err := New(&ToukaJWTMiddleware{
		Realm:    "analysis",
		Key:      testPrivateKey(t),
		TimeFunc: func() time.Time { return now },
		Authenticator: func(c *touka.Context) (any, error) {
			return "admin", nil
		},
		PayloadFunc: func(data any) MapClaims {
			return MapClaims{"identity": data}
		},
	})
	require.NoError(t, err)

	handler := toukaHandler(auth)
	r := gofight.New()

	var accessToken string
	r.POST("/login").Run(handler, func(resp gofight.HTTPResponse, req gofight.HTTPRequest) {
		require.Equal(t, http.StatusOK, resp.Code)
		accessToken = gjson.Get(resp.Body.String(), "access_token").String()
		require.NotEmpty(t, accessToken)
	})

	now = now.Add(auth.Timeout + time.Minute)

	r.GET("/auth/hello").SetHeader(gofight.H{"Authorization": "Bearer " + accessToken}).Run(handler, func(resp gofight.HTTPResponse, req gofight.HTTPRequest) {
		assert.Equal(t, http.StatusUnauthorized, resp.Code)
		assert.Contains(t, resp.Body.String(), ErrExpiredToken.Error())
	})
}

func TestAnalysisConfirmExpiredTokenStillRejectedWithoutClaimsValidation(t *testing.T) {
	now := time.Now()
	auth, err := New(&ToukaJWTMiddleware{
		Realm:        "analysis",
		Key:          testPrivateKey(t),
		TimeFunc:     func() time.Time { return now },
		ParseOptions: []jwt.ParserOption{jwt.WithoutClaimsValidation()},
		Authenticator: func(c *touka.Context) (any, error) {
			return "admin", nil
		},
		PayloadFunc: func(data any) MapClaims {
			return MapClaims{"identity": data}
		},
	})
	require.NoError(t, err)

	handler := toukaHandler(auth)
	r := gofight.New()

	var accessToken string
	r.POST("/login").Run(handler, func(resp gofight.HTTPResponse, req gofight.HTTPRequest) {
		require.Equal(t, http.StatusOK, resp.Code)
		accessToken = gjson.Get(resp.Body.String(), "access_token").String()
		require.NotEmpty(t, accessToken)
	})

	now = now.Add(auth.Timeout + time.Minute)

	r.GET("/auth/hello").SetHeader(gofight.H{"Authorization": "Bearer " + accessToken}).Run(handler, func(resp gofight.HTTPResponse, req gofight.HTTPRequest) {
		assert.Equal(t, http.StatusUnauthorized, resp.Code)
		assert.Contains(t, resp.Body.String(), ErrExpiredToken.Error())
	})
}

func TestAnalysisConfirmCountIncludesExpiredTokens(t *testing.T) {
	s := store.NewInMemoryRefreshTokenStore()
	err := s.Set(context.Background(), "expired-token", "admin", time.Now().Add(-time.Second))
	require.NoError(t, err)

	count, err := s.Count(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestAnalysisConfirmInMemoryStoreUsesMiddlewareClock(t *testing.T) {
	now := time.Now()
	mw, err := New(&ToukaJWTMiddleware{
		Realm:    "analysis",
		Key:      testPrivateKey(t),
		TimeFunc: func() time.Time { return now },
	})
	require.NoError(t, err)

	tokenPair, err := mw.TokenGenerator(context.Background(), "admin")
	require.NoError(t, err)

	now = now.Add(mw.RefreshTokenTimeout + time.Second)
	_, err = mw.TokenStore.Get(context.Background(), tokenPair.RefreshToken)
	assert.ErrorIs(t, err, core.ErrRefreshTokenExpired)
}

func TestAnalysisConfirmCookieSameSiteIgnored(t *testing.T) {
	mw, err := New(&ToukaJWTMiddleware{
		Realm:          "analysis",
		Key:            testPrivateKey(t),
		SendCookie:     true,
		CookieSameSite: http.SameSiteStrictMode,
	})
	require.NoError(t, err)

	w := httptest.NewRecorder()
	c, _ := touka.CreateTestContext(w)
	mw.SetCookie(c, "access-token")

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, http.SameSiteStrictMode, cookies[0].SameSite)
	assert.Contains(t, w.Header().Get("Set-Cookie"), "SameSite=Strict")
}

func TestAnalysisConfirmAccessCookieDefaultsRemainConfigurable(t *testing.T) {
	mw, err := New(&ToukaJWTMiddleware{
		Realm:      "analysis",
		Key:        testPrivateKey(t),
		SendCookie: true,
	})
	require.NoError(t, err)

	w := httptest.NewRecorder()
	c, _ := touka.CreateTestContext(w)
	mw.SetCookie(c, "access-token")

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.False(t, cookies[0].Secure)
	assert.False(t, cookies[0].HttpOnly)
}

func TestAnalysisConfirmAccessCookieTracksTimeoutFunc(t *testing.T) {
	mw, err := New(&ToukaJWTMiddleware{
		Realm:      "analysis",
		Key:        testPrivateKey(t),
		SendCookie: true,
		Timeout:    time.Hour,
		TimeoutFunc: func(data any) time.Duration {
			return 10 * time.Minute
		},
	})
	require.NoError(t, err)

	w := httptest.NewRecorder()
	c, _ := touka.CreateTestContext(w)
	mw.setAccessTokenCookie(c, "access-token", mw.TimeFunc().Add(10*time.Minute).Unix())

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.InDelta(t, 600, cookies[0].MaxAge, 1)
}

func TestAnalysisConfirmAccessCookiePrefersConfiguredMaxAge(t *testing.T) {
	mw, err := New(&ToukaJWTMiddleware{
		Realm:        "analysis",
		Key:          testPrivateKey(t),
		SendCookie:   true,
		CookieMaxAge: 2 * time.Minute,
		Timeout:      time.Hour,
	})
	require.NoError(t, err)

	w := httptest.NewRecorder()
	c, _ := touka.CreateTestContext(w)
	mw.setAccessTokenCookie(c, "access-token", mw.TimeFunc().Add(10*time.Minute).Unix())

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.InDelta(t, 120, cookies[0].MaxAge, 1)
}

func TestAnalysisConfirmRefreshCookieLifetimeTracksRemainingWindow(t *testing.T) {
	mw, err := New(&ToukaJWTMiddleware{
		Realm:               "analysis",
		Key:                 testPrivateKey(t),
		SendCookie:          true,
		RefreshTokenTimeout: time.Hour,
	})
	require.NoError(t, err)

	w := httptest.NewRecorder()
	c, _ := touka.CreateTestContext(w)
	expiresAt := mw.TimeFunc().Add(10 * time.Minute).Unix()
	mw.SetRefreshTokenCookie(c, "refresh-token", expiresAt)

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.InDelta(t, 600, cookies[0].MaxAge, 1)
}

func TestAnalysisConfirmMaxRefreshSurvivesSerializedStore(t *testing.T) {
	auth, err := New(&ToukaJWTMiddleware{
		Realm:      "analysis",
		Key:        testPrivateKey(t),
		MaxRefresh: 3 * time.Second,
		TokenStore: &jsonRoundTripStore{tokens: map[string][]byte{}},
		Authenticator: func(c *touka.Context) (any, error) {
			return "admin", nil
		},
		PayloadFunc: func(data any) MapClaims {
			return MapClaims{"identity": data}
		},
	})
	require.NoError(t, err)

	handler := toukaHandler(auth)
	r := gofight.New()

	var refreshToken string
	r.POST("/login").Run(handler, func(resp gofight.HTTPResponse, req gofight.HTTPRequest) {
		require.Equal(t, http.StatusOK, resp.Code)
		refreshToken = gjson.Get(resp.Body.String(), "refresh_token").String()
		require.NotEmpty(t, refreshToken)
	})

	time.Sleep(100 * time.Millisecond)

	r.POST("/refresh").SetForm(gofight.H{"refresh_token": refreshToken}).Run(handler, func(resp gofight.HTTPResponse, req gofight.HTTPRequest) {
		require.Equal(t, http.StatusOK, resp.Code)
		refreshToken = gjson.Get(resp.Body.String(), "refresh_token").String()
		require.NotEmpty(t, refreshToken)
	})

	time.Sleep(3200 * time.Millisecond)

	r.POST("/refresh").SetForm(gofight.H{"refresh_token": refreshToken}).Run(handler, func(resp gofight.HTTPResponse, req gofight.HTTPRequest) {
		assert.Equal(t, http.StatusUnauthorized, resp.Code)
	})
}

func TestAnalysisConfirmMaxRefreshSurvivesMapStore(t *testing.T) {
	auth, err := New(&ToukaJWTMiddleware{
		Realm:      "analysis",
		Key:        testPrivateKey(t),
		MaxRefresh: 3 * time.Second,
		TokenStore: &mapRoundTripStore{tokens: map[string][]byte{}},
		Authenticator: func(c *touka.Context) (any, error) {
			return "admin", nil
		},
		PayloadFunc: func(data any) MapClaims {
			return MapClaims{"identity": data}
		},
	})
	require.NoError(t, err)

	handler := toukaHandler(auth)
	r := gofight.New()

	var refreshToken string
	r.POST("/login").Run(handler, func(resp gofight.HTTPResponse, req gofight.HTTPRequest) {
		require.Equal(t, http.StatusOK, resp.Code)
		refreshToken = gjson.Get(resp.Body.String(), "refresh_token").String()
		require.NotEmpty(t, refreshToken)
	})

	time.Sleep(100 * time.Millisecond)

	r.POST("/refresh").SetForm(gofight.H{"refresh_token": refreshToken}).Run(handler, func(resp gofight.HTTPResponse, req gofight.HTTPRequest) {
		require.Equal(t, http.StatusOK, resp.Code)
		refreshToken = gjson.Get(resp.Body.String(), "refresh_token").String()
		require.NotEmpty(t, refreshToken)
	})

	time.Sleep(3200 * time.Millisecond)

	r.POST("/refresh").SetForm(gofight.H{"refresh_token": refreshToken}).Run(handler, func(resp gofight.HTTPResponse, req gofight.HTTPRequest) {
		assert.Equal(t, http.StatusUnauthorized, resp.Code)
	})
}

func TestAnalysisConfirmRefreshRotationRequiresAtomicStore(t *testing.T) {
	auth, err := New(&ToukaJWTMiddleware{
		Realm: "analysis",
		Key:   testPrivateKey(t),
		Authenticator: func(c *touka.Context) (any, error) {
			return "admin", nil
		},
		PayloadFunc: func(data any) MapClaims {
			return MapClaims{"identity": data}
		},
	})
	require.NoError(t, err)
	store := &slowFallbackStore{tokens: map[string]any{"old-refresh": "admin"}}
	auth.TokenStore = store

	err = auth.rotateRefreshToken(context.Background(), "old-refresh", "new-refresh", "admin")
	assert.ErrorIs(t, err, ErrUnsafeRefreshRotation)
	_, exists := store.tokens["old-refresh"]
	assert.True(t, exists)
	_, exists = store.tokens["new-refresh"]
	assert.False(t, exists)
}

func TestAnalysisConfirmLogoutStillRevokesNonAtomicStoreToken(t *testing.T) {
	auth, err := New(&ToukaJWTMiddleware{
		Realm: "analysis",
		Key:   testPrivateKey(t),
		Authenticator: func(c *touka.Context) (any, error) {
			return "admin", nil
		},
		PayloadFunc: func(data any) MapClaims {
			return MapClaims{"identity": data}
		},
	})
	require.NoError(t, err)
	store := &slowFallbackStore{tokens: map[string]any{"old-refresh": "admin"}}
	auth.TokenStore = store

	w := httptest.NewRecorder()
	c, _ := touka.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: auth.RefreshTokenCookieName, Value: "old-refresh"})
	c.Request = req
	auth.LogoutHandler(c)

	_, exists := store.tokens["old-refresh"]
	assert.False(t, exists)
	_, exists = store.tokens["new-refresh"]
	assert.False(t, exists)
}

func TestAnalysisConfirmLogoutBlocksConcurrentRefreshOfSuccessor(t *testing.T) {
	h := newHS512Helper()
	auth, err := New(h.middleware())
	require.NoError(t, err)

	refreshTokenChainMu.Lock()
	refreshTokenChain = map[string]refreshTokenChainEntry{}
	refreshTokenChainSweeps = 0
	refreshTokenChainMu.Unlock()

	store := &scriptedRotatorStore{
		tokens: map[string]any{
			"r1": "admin",
			"r2": "admin",
		},
		rotateStarted:     make(chan struct{}),
		allowRotateFinish: make(chan struct{}),
	}
	auth.TokenStore = store

	setRefreshTokenSuccessor("r1", "r2", time.Now().Add(time.Minute), time.Now())

	rotateDone := make(chan error, 1)
	go func() {
		rotateDone <- auth.rotateRefreshToken(context.Background(), "r2", "r3", "admin")
	}()

	<-store.rotateStarted

	w := httptest.NewRecorder()
	c, _ := touka.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: auth.RefreshTokenCookieName, Value: "r1"})
	c.Request = req

	logoutDone := make(chan struct{})
	go func() {
		auth.LogoutHandler(c)
		close(logoutDone)
	}()

	select {
	case <-logoutDone:
		t.Fatal("logout completed before successor rotation lock was released")
	case <-time.After(50 * time.Millisecond):
	}

	close(store.allowRotateFinish)
	err = <-rotateDone
	assert.NoError(t, err)
	<-logoutDone

	_, exists := store.tokens["r1"]
	assert.False(t, exists)
	_, exists = store.tokens["r2"]
	assert.False(t, exists)
	_, exists = store.tokens["r3"]
	assert.False(t, exists)
	assert.Equal(t, "", nextRefreshToken("r1", time.Now()))
	assert.Equal(t, "", nextRefreshToken("r2", time.Now()))
}

func TestAnalysisConfirmRefreshTokenChainSweepsExpiredEntries(t *testing.T) {
	refreshTokenChainMu.Lock()
	refreshTokenChain = map[string]refreshTokenChainEntry{}
	refreshTokenChainSweeps = refreshTokenChainSweepAt - 1
	refreshTokenChainMu.Unlock()

	now := time.Now()
	setRefreshTokenSuccessor("expired", "stale", now.Add(-time.Second), now)
	setRefreshTokenSuccessor("active", "fresh", now.Add(time.Minute), now)

	assert.Equal(t, "", nextRefreshToken("expired", now))
	assert.Equal(t, "fresh", nextRefreshToken("active", now))
}

func TestAnalysisConfirmRefreshCanSucceedAfterExpiryBoundary(t *testing.T) {
	auth, err := New(&ToukaJWTMiddleware{
		Realm:               "analysis",
		Key:                 testPrivateKey(t),
		RefreshTokenTimeout: 200 * time.Millisecond,
		Authenticator: func(c *touka.Context) (any, error) {
			return "admin", nil
		},
		PayloadFunc: func(data any) MapClaims {
			time.Sleep(350 * time.Millisecond)
			return MapClaims{"identity": data}
		},
	})
	require.NoError(t, err)

	handler := toukaHandler(auth)
	r := gofight.New()

	var refreshToken string
	r.POST("/login").Run(handler, func(resp gofight.HTTPResponse, req gofight.HTTPRequest) {
		require.Equal(t, http.StatusOK, resp.Code)
		refreshToken = gjson.Get(resp.Body.String(), "refresh_token").String()
		require.NotEmpty(t, refreshToken)
	})

	r.POST("/refresh").SetForm(gofight.H{"refresh_token": refreshToken}).Run(handler, func(resp gofight.HTTPResponse, req gofight.HTTPRequest) {
		assert.Equal(t, http.StatusUnauthorized, resp.Code)
		assert.Contains(t, resp.Body.String(), "refresh token expired")
	})
}

type jsonRoundTripStore struct {
	tokens map[string][]byte
	expiry map[string]time.Time
}

func (s *jsonRoundTripStore) Set(ctx context.Context, token string, userData any, expiry time.Time) error {
	if s.expiry == nil {
		s.expiry = map[string]time.Time{}
	}
	encoded, err := json.Marshal(userData)
	if err != nil {
		return err
	}
	s.tokens[token] = encoded
	s.expiry[token] = expiry
	return nil
}

func (s *jsonRoundTripStore) Get(ctx context.Context, token string) (any, error) {
	encoded, ok := s.tokens[token]
	if !ok {
		return nil, core.ErrRefreshTokenNotFound
	}
	if !time.Now().Before(s.expiry[token]) {
		delete(s.tokens, token)
		delete(s.expiry, token)
		return nil, core.ErrRefreshTokenExpired
	}
	var state core.RefreshTokenState
	if err := json.Unmarshal(encoded, &state); err != nil {
		return nil, err
	}
	return state, nil
}

func (s *jsonRoundTripStore) Delete(ctx context.Context, token string) error {
	delete(s.tokens, token)
	delete(s.expiry, token)
	return nil
}

func (s *jsonRoundTripStore) Rotate(ctx context.Context, oldToken, newToken string, userData any, expiry time.Time) error {
	if _, err := s.Get(ctx, oldToken); err != nil {
		return err
	}
	if err := s.Set(ctx, newToken, userData, expiry); err != nil {
		return err
	}
	return s.Delete(ctx, oldToken)
}

func (s *jsonRoundTripStore) Cleanup(ctx context.Context) (int, error) {
	return 0, nil
}

func (s *jsonRoundTripStore) Count(ctx context.Context) (int, error) {
	return len(s.tokens), nil
}

type mapRoundTripStore struct {
	tokens map[string][]byte
	expiry map[string]time.Time
}

func (s *mapRoundTripStore) Set(ctx context.Context, token string, userData any, expiry time.Time) error {
	if s.expiry == nil {
		s.expiry = map[string]time.Time{}
	}
	encoded, err := json.Marshal(userData)
	if err != nil {
		return err
	}
	s.tokens[token] = encoded
	s.expiry[token] = expiry
	return nil
}

func (s *mapRoundTripStore) Get(ctx context.Context, token string) (any, error) {
	encoded, ok := s.tokens[token]
	if !ok {
		return nil, core.ErrRefreshTokenNotFound
	}
	if !time.Now().Before(s.expiry[token]) {
		delete(s.tokens, token)
		delete(s.expiry, token)
		return nil, core.ErrRefreshTokenExpired
	}
	var state map[string]any
	if err := json.Unmarshal(encoded, &state); err != nil {
		return nil, err
	}
	return state, nil
}

func (s *mapRoundTripStore) Delete(ctx context.Context, token string) error {
	delete(s.tokens, token)
	delete(s.expiry, token)
	return nil
}

func (s *mapRoundTripStore) Rotate(ctx context.Context, oldToken, newToken string, userData any, expiry time.Time) error {
	if _, err := s.Get(ctx, oldToken); err != nil {
		return err
	}
	if err := s.Set(ctx, newToken, userData, expiry); err != nil {
		return err
	}
	return s.Delete(ctx, oldToken)
}

func (s *mapRoundTripStore) Cleanup(ctx context.Context) (int, error) {
	return 0, nil
}

func (s *mapRoundTripStore) Count(ctx context.Context) (int, error) {
	return len(s.tokens), nil
}

type slowFallbackStore struct {
	mu     sync.Mutex
	tokens map[string]any
}

type scriptedRotatorStore struct {
	mu                sync.Mutex
	tokens            map[string]any
	rotateStarted     chan struct{}
	allowRotateFinish chan struct{}
	rotateOnce        sync.Once
}

func (s *scriptedRotatorStore) Set(ctx context.Context, token string, userData any, expiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token] = userData
	return nil
}

func (s *scriptedRotatorStore) Get(ctx context.Context, token string) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.tokens[token]
	if !ok {
		return nil, core.ErrRefreshTokenNotFound
	}
	return data, nil
}

func (s *scriptedRotatorStore) Delete(ctx context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, token)
	return nil
}

func (s *scriptedRotatorStore) Rotate(ctx context.Context, oldToken, newToken string, userData any, expiry time.Time) error {
	s.rotateOnce.Do(func() {
		close(s.rotateStarted)
	})
	<-s.allowRotateFinish
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tokens[oldToken]; !ok {
		return core.ErrRefreshTokenNotFound
	}
	delete(s.tokens, oldToken)
	s.tokens[newToken] = userData
	return nil
}

func (s *scriptedRotatorStore) Cleanup(ctx context.Context) (int, error) {
	return 0, nil
}

func (s *scriptedRotatorStore) Count(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tokens), nil
}

func (s *slowFallbackStore) Set(ctx context.Context, token string, userData any, expiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token] = userData
	return nil
}

func (s *slowFallbackStore) Get(ctx context.Context, token string) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.tokens[token]
	if !ok {
		return nil, core.ErrRefreshTokenNotFound
	}
	return data, nil
}

func (s *slowFallbackStore) Delete(ctx context.Context, token string) error {
	time.Sleep(50 * time.Millisecond)
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, token)
	return nil
}

func (s *slowFallbackStore) Cleanup(ctx context.Context) (int, error) {
	return 0, nil
}

func (s *slowFallbackStore) Count(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tokens), nil
}
