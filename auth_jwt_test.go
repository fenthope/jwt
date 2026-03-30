package jwt

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/appleboy/gofight/v2"
	"github.com/fenthope/jwt/store"
	"github.com/golang-jwt/jwt/v5"
	"github.com/infinite-iroha/touka"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

var (
	key                  = []byte("secret key")
	defaultAuthenticator = func(c *touka.Context) (any, error) {
		userID := c.PostForm("username")
		password := c.PostForm("password")
		if userID == "" || password == "" {
			return "", ErrMissingLoginValues
		}
		if userID == "admin" && password == "admin" {
			return userID, nil
		}
		return userID, ErrFailedAuthentication
	}
)

type failingRotateStore struct {
	*store.InMemoryRefreshTokenStore
}

func (s *failingRotateStore) Rotate(ctx context.Context, oldToken, newToken string, userData any, expiry time.Time) error {
	return errors.New("rotate failed")
}

func makeTokenString(username string) string {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["identity"] = username
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	claims["iat"] = time.Now().Unix()
	claims["orig_iat"] = time.Now().Unix()
	s, _ := token.SignedString(key)
	return s
}

func makeTokenWithClaims(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := token.SignedString(key)
	require.NoError(t, err)
	return s
}

func toukaHandler(auth *ToukaJWTMiddleware) *touka.Engine {
	r := touka.New()
	r.POST("/login", auth.LoginHandler)
	r.POST("/logout", auth.LogoutHandler)
	r.GET("/refresh", auth.RefreshHandler)

	authGroup := r.Group("/auth")
	authGroup.Use(auth.MiddlewareFunc())
	{
		authGroup.GET("/hello", func(c *touka.Context) {
			claims := ExtractClaims(c)
			c.JSON(200, touka.H{"userID": claims["identity"]})
		})
	}
	return r
}

func TestDualTokenFlow(t *testing.T) {
	auth, _ := New(&ToukaJWTMiddleware{
		Realm: "test",
		Key:   key,
		Authenticator: func(c *touka.Context) (any, error) {
			return "admin", nil
		},
		PayloadFunc: func(data any) MapClaims {
			return MapClaims{"identity": data}
		},
	})
	handler := toukaHandler(auth)
	r := gofight.New()

	var accessToken, refreshToken string

	// 1. Login
	r.POST("/login").Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
		assert.Equal(t, 200, r.Code)
		accessToken = gjson.Get(r.Body.String(), "access_token").String()
		refreshToken = gjson.Get(r.Body.String(), "refresh_token").String()
		assert.NotEmpty(t, accessToken)
		assert.NotEmpty(t, refreshToken)
	})

	// 2. Use access token
	r.GET("/auth/hello").SetHeader(gofight.H{"Authorization": "Bearer " + accessToken}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, 200, r.Code)
			assert.Equal(t, "admin", gjson.Get(r.Body.String(), "userID").String())
		})

	// 3. Refresh token
	time.Sleep(time.Second)
	r.GET("/refresh?refresh_token="+refreshToken).Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
		assert.Equal(t, 200, r.Code)
		newAccessToken := gjson.Get(r.Body.String(), "access_token").String()
		assert.NotEmpty(t, newAccessToken)
		assert.NotEqual(t, accessToken, newAccessToken)
	})

	// 4. Try old refresh token (should fail as it was deleted upon refresh)
	r.GET("/refresh?refresh_token="+refreshToken).Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
		assert.Equal(t, 401, r.Code)
	})
}

func TestMiddleware(t *testing.T) {
	auth, _ := New(&ToukaJWTMiddleware{
		Realm:         "test",
		Key:           key,
		Authenticator: defaultAuthenticator,
	})
	handler := toukaHandler(auth)
	r := gofight.New()

	r.GET("/auth/hello").Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
		assert.Equal(t, http.StatusUnauthorized, r.Code)
	})

	r.GET("/auth/hello").SetHeader(gofight.H{"Authorization": "Bearer " + makeTokenString("admin")}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
}

func TestSetCookie(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := touka.CreateTestContext(w)
	mw, _ := New(&ToukaJWTMiddleware{
		Realm:      "test",
		Key:        key,
		SendCookie: true,
		CookieName: "jwt",
	})
	mw.SetCookie(c, "test-token")
	cookies := w.Result().Cookies()
	assert.Len(t, cookies, 1)
	assert.Equal(t, "jwt", cookies[0].Name)
}

func TestRefreshCookieDefaultsFollowAccessCookieSettings(t *testing.T) {
	defaultMW, err := New(&ToukaJWTMiddleware{
		Realm:          "test",
		Key:            key,
		SendCookie:     true,
		SecureCookie:   true,
		CookieHTTPOnly: true,
	})
	require.NoError(t, err)
	assert.True(t, defaultMW.RefreshTokenSecureCookie)
	assert.True(t, defaultMW.RefreshTokenCookieHTTPOnly)
}

func TestMissingAuthenticator(t *testing.T) {
	mw, _ := New(&ToukaJWTMiddleware{Realm: "test", Key: key})
	handler := toukaHandler(mw)
	r := gofight.New()
	r.POST("/login").Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
		assert.Equal(t, 500, r.Code)
	})
}

func TestLogout(t *testing.T) {
	auth, _ := New(&ToukaJWTMiddleware{
		Realm:      "test",
		Key:        key,
		SendCookie: true,
	})
	handler := toukaHandler(auth)
	r := gofight.New()
	r.POST("/logout").Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
		assert.Equal(t, 200, r.Code)
		setCookies := r.HeaderMap["Set-Cookie"]
		foundJwt, foundRefresh := false, false
		for _, c := range setCookies {
			if strings.Contains(c, "jwt=; Path=/; Max-Age=0") {
				foundJwt = true
			}
			if strings.Contains(c, "refresh_token=; Path=/; Max-Age=0") {
				foundRefresh = true
			}
		}
		assert.True(t, foundJwt)
		assert.True(t, foundRefresh)
	})
}

func TestExpiredToken(t *testing.T) {
	auth, _ := New(&ToukaJWTMiddleware{
		Realm: "test",
		Key:   key,
	})
	handler := toukaHandler(auth)
	r := gofight.New()

	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["identity"] = "admin"
	claims["exp"] = time.Now().Add(-time.Hour).Unix()
	s, _ := token.SignedString(key)

	r.GET("/auth/hello").SetHeader(gofight.H{"Authorization": "Bearer " + s}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, 401, r.Code)
			assert.Contains(t, r.Body.String(), "token is expired")
		})
}

func TestTokenGeneratorAddsStandardIssuedAt(t *testing.T) {
	now := time.Unix(1700000000, 0)
	auth, err := New(&ToukaJWTMiddleware{
		Realm:    "test",
		Key:      key,
		TimeFunc: func() time.Time { return now },
	})
	require.NoError(t, err)

	tokenPair, err := auth.TokenGenerator(context.Background(), "admin")
	require.NoError(t, err)

	parsed, err := jwt.Parse(tokenPair.AccessToken, func(token *jwt.Token) (any, error) {
		return key, nil
	}, jwt.WithTimeFunc(func() time.Time { return now }))
	require.NoError(t, err)
	claims := parsed.Claims.(jwt.MapClaims)
	assert.Equal(t, float64(now.Unix()), claims["iat"])
	assert.Equal(t, float64(now.Unix()), claims["orig_iat"])
}

func TestMiddlewareRejectsTokenWithoutExpByDefault(t *testing.T) {
	auth, err := New(&ToukaJWTMiddleware{
		Realm: "test",
		Key:   key,
	})
	require.NoError(t, err)
	handler := toukaHandler(auth)
	r := gofight.New()

	token := makeTokenWithClaims(t, jwt.MapClaims{
		"identity": "admin",
		"iat":      time.Now().Unix(),
	})

	r.GET("/auth/hello").SetHeader(gofight.H{"Authorization": "Bearer " + token}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
		})
}

func TestMiddlewareRejectsTokenNotValidYet(t *testing.T) {
	auth, err := New(&ToukaJWTMiddleware{
		Realm: "test",
		Key:   key,
	})
	require.NoError(t, err)
	handler := toukaHandler(auth)
	r := gofight.New()

	token := makeTokenWithClaims(t, jwt.MapClaims{
		"identity": "admin",
		"exp":      time.Now().Add(time.Hour).Unix(),
		"nbf":      time.Now().Add(time.Hour).Unix(),
		"iat":      time.Now().Unix(),
	})

	r.GET("/auth/hello").SetHeader(gofight.H{"Authorization": "Bearer " + token}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
			assert.Contains(t, r.Body.String(), "token is not valid yet")
		})
}

func TestRefreshTokenRotateSucceedsOnceInMemoryStore(t *testing.T) {
	s := store.NewInMemoryRefreshTokenStore()
	err := s.Set(context.Background(), "refresh-token", "admin", time.Now().Add(time.Hour))
	require.NoError(t, err)

	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.Rotate(context.Background(), "refresh-token", makeTokenString("next"), "admin", time.Now().Add(time.Hour))
			results <- err
		}()
	}
	wg.Wait()
	close(results)

	var okCount, notFoundCount int
	for err := range results {
		if err == nil {
			okCount++
			continue
		}
		if errors.Is(err, store.ErrRefreshTokenNotFound) {
			notFoundCount++
		}
	}
	assert.Equal(t, 1, okCount)
	assert.Equal(t, 1, notFoundCount)
}

func TestRefreshHandlerPreservesOldTokenWhenRotationFails(t *testing.T) {
	tokenStore := &failingRotateStore{InMemoryRefreshTokenStore: store.NewInMemoryRefreshTokenStore()}
	err := tokenStore.Set(context.Background(), "refresh-token", "admin", time.Now().Add(time.Hour))
	require.NoError(t, err)

	auth, err := New(&ToukaJWTMiddleware{
		Realm:      "test",
		Key:        key,
		TokenStore: tokenStore,
	})
	require.NoError(t, err)

	handler := toukaHandler(auth)
	r := gofight.New()
	r.GET("/refresh?refresh_token=refresh-token").Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
		assert.Equal(t, http.StatusInternalServerError, r.Code)
	})

	userData, err := tokenStore.Get(context.Background(), "refresh-token")
	require.NoError(t, err)
	assert.Equal(t, "admin", userData)
}

func TestHTTPStatusMessageFunc(t *testing.T) {
	customErr := errors.New("custom error")
	auth, _ := New(&ToukaJWTMiddleware{
		Realm: "test",
		Key:   key,
		HTTPStatusMessageFunc: func(e error, c *touka.Context) string {
			if e == customErr {
				return "CUSTOM MESSAGE"
			}
			return e.Error()
		},
	})
	msg := auth.HTTPStatusMessageFunc(customErr, nil)
	assert.Equal(t, "CUSTOM MESSAGE", msg)
}
