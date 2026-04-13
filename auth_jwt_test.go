package jwt

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"filippo.io/mldsa"
	"github.com/appleboy/gofight/v2"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/infinite-iroha/touka"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/fenthope/jwt/core"
)

var (
	// Tests intentionally use fixed valid seeds so signatures are deterministic
	// and failures remain reproducible across runs.
	defaultSeed          = []byte("01234567890123456789012345678901")
	secondarySeed        = []byte("abcdefghijklmnopqrstuvwxyz012345")
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

func makeTokenString(t *testing.T, key *mldsa.PrivateKey, username string) string {
	t.Helper()
	token := jwtlib.New(SigningMethodMLDSA65)
	claims := token.Claims.(jwtlib.MapClaims)
	claims["identity"] = username
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	claims["orig_iat"] = time.Now().Unix()
	s, err := token.SignedString(key)
	require.NoError(t, err)
	return s
}

func makeTokenWithClaims(t *testing.T, key *mldsa.PrivateKey, claims jwtlib.MapClaims) string {
	t.Helper()
	token := jwtlib.NewWithClaims(SigningMethodMLDSA65, claims)
	s, err := token.SignedString(key)
	require.NoError(t, err)
	return s
}

func testPrivateKey(t *testing.T) *mldsa.PrivateKey {
	t.Helper()
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), defaultSeed)
	require.NoError(t, err)
	return key
}

func testPublicKey(t *testing.T) *mldsa.PublicKey {
	t.Helper()
	return testPrivateKey(t).PublicKey()
}

func toukaHandler(auth *ToukaJWTMiddleware) *touka.Engine {
	r := touka.New()
	r.POST("/login", auth.LoginHandler)
	r.POST("/logout", auth.LogoutHandler)
	r.POST("/refresh", auth.RefreshHandler)

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

func TestMiddlewareInitDefaultsToMLDSA65(t *testing.T) {
	mw, err := New(&ToukaJWTMiddleware{
		Realm:       "test",
		Key:         testPrivateKey(t),
		TokenLookup: "header:Authorization",
	})
	require.NoError(t, err)
	assert.Equal(t, SigningAlgorithmMLDSA65, mw.SigningAlgorithm)
	assert.NotNil(t, mw.algorithm)
	assert.NotNil(t, mw.verifyKey)
}

func TestMiddlewareInitRejectsUnsupportedAlgorithm(t *testing.T) {
	_, err := New(&ToukaJWTMiddleware{
		Realm:            "test",
		Key:              testPrivateKey(t),
		SigningAlgorithm: "HS256",
	})
	assert.ErrorIs(t, err, ErrInvalidSigningAlgorithm)
}

func TestMiddlewareInitLoadsKeysFromSeedBytes(t *testing.T) {
	mw, err := New(&ToukaJWTMiddleware{
		Realm:        "test",
		PrivKeyBytes: defaultSeed,
		PubKeyBytes:  testPublicKey(t).Bytes(),
	})
	require.NoError(t, err)
	assert.NotNil(t, mw.Key)
	assert.NotNil(t, mw.verifyKey)
	verifyKey, err := mw.algorithm.VerificationKeyFromSigningKey(mw.Key)
	require.NoError(t, err)
	assert.Equal(t, verifyKey, mw.verifyKey)
}

func TestMiddlewareInitSupportsVerifyOnlyMode(t *testing.T) {
	mw, err := New(&ToukaJWTMiddleware{
		Realm:       "test",
		PubKeyBytes: testPublicKey(t).Bytes(),
	})
	require.NoError(t, err)
	assert.Nil(t, mw.Key)
	assert.NotNil(t, mw.verifyKey)

	w := httptest.NewRecorder()
	c, _ := touka.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/auth/hello", nil)
	req.Header.Set("Authorization", "Bearer "+makeTokenString(t, testPrivateKey(t), "admin"))
	c.Request = req
	parsed, err := mw.ParseToken(c)
	require.NoError(t, err)
	assert.True(t, parsed.Valid)

	_, err = mw.TokenGenerator(t.Context(), "admin")
	assert.ErrorIs(t, err, ErrMissingPrivateKey)
}

func TestMiddlewareInitRequiresUsablePrivateKey(t *testing.T) {
	_, err := New(&ToukaJWTMiddleware{Realm: "test"})
	assert.ErrorIs(t, err, ErrMissingSecretKey)
}

func TestMiddlewareInitRejectsInvalidPrivateKeySeed(t *testing.T) {
	_, err := New(&ToukaJWTMiddleware{
		Realm:        "test",
		PrivKeyBytes: []byte("short"),
	})
	assert.ErrorIs(t, err, ErrInvalidPrivKey)
}

func TestMiddlewareInitRejectsInvalidPublicKeyBytes(t *testing.T) {
	_, err := New(&ToukaJWTMiddleware{
		Realm:        "test",
		PrivKeyBytes: defaultSeed,
		PubKeyBytes:  []byte("bad-public-key"),
	})
	assert.ErrorIs(t, err, ErrInvalidPubKey)
}

func TestDualTokenFlow(t *testing.T) {
	auth, err := New(&ToukaJWTMiddleware{
		Realm: "test",
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

	var accessToken, refreshToken string

	r.POST("/login").Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
		assert.Equal(t, 200, r.Code)
		accessToken = gjson.Get(r.Body.String(), "access_token").String()
		refreshToken = gjson.Get(r.Body.String(), "refresh_token").String()
		assert.NotEmpty(t, accessToken)
		assert.NotEmpty(t, refreshToken)
	})

	r.GET("/auth/hello").SetHeader(gofight.H{"Authorization": "Bearer " + accessToken}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, 200, r.Code)
			assert.Equal(t, "admin", gjson.Get(r.Body.String(), "userID").String())
		})

	time.Sleep(time.Second)
	r.POST("/refresh").SetForm(gofight.H{"refresh_token": refreshToken}).Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
		assert.Equal(t, 200, r.Code)
		newAccessToken := gjson.Get(r.Body.String(), "access_token").String()
		assert.NotEmpty(t, newAccessToken)
		assert.NotEqual(t, accessToken, newAccessToken)
	})

	r.POST("/refresh").SetForm(gofight.H{"refresh_token": refreshToken}).Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
		assert.Equal(t, 401, r.Code)
	})
}

func TestMiddleware(t *testing.T) {
	auth, err := New(&ToukaJWTMiddleware{
		Realm:         "test",
		Key:           testPrivateKey(t),
		Authenticator: defaultAuthenticator,
	})
	require.NoError(t, err)
	handler := toukaHandler(auth)
	r := gofight.New()

	r.GET("/auth/hello").Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
		assert.Equal(t, http.StatusUnauthorized, r.Code)
	})

	r.GET("/auth/hello").SetHeader(gofight.H{"Authorization": "Bearer " + makeTokenString(t, testPrivateKey(t), "admin")}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, http.StatusOK, r.Code)
		})
}

func TestSetCookie(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := touka.CreateTestContext(w)
	mw, err := New(&ToukaJWTMiddleware{
		Realm:      "test",
		Key:        testPrivateKey(t),
		SendCookie: true,
		CookieName: "jwt",
	})
	require.NoError(t, err)
	mw.SetCookie(c, "test-token")
	cookies := w.Result().Cookies()
	assert.Len(t, cookies, 1)
	assert.Equal(t, "jwt", cookies[0].Name)
}

func TestSetRefreshTokenCookie(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := touka.CreateTestContext(w)
	mw, err := New(&ToukaJWTMiddleware{
		Realm:                    "test",
		Key:                      testPrivateKey(t),
		SendCookie:               true,
		RefreshTokenTimeout:      2 * time.Hour,
		RefreshTokenCookieName:   "refresh",
		RefreshTokenSecureCookie: true,
	})
	require.NoError(t, err)
	mw.SetRefreshTokenCookie(c, "refresh-token")
	cookies := w.Result().Cookies()
	assert.Len(t, cookies, 1)
	assert.Equal(t, "refresh", cookies[0].Name)
	assert.Equal(t, 7200, cookies[0].MaxAge)
	assert.True(t, cookies[0].Secure)
}

func TestMissingAuthenticator(t *testing.T) {
	mw, err := New(&ToukaJWTMiddleware{Realm: "test", Key: testPrivateKey(t)})
	require.NoError(t, err)
	handler := toukaHandler(mw)
	r := gofight.New()
	r.POST("/login").Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
		assert.Equal(t, 500, r.Code)
	})
}

func TestLogout(t *testing.T) {
	auth, err := New(&ToukaJWTMiddleware{
		Realm:      "test",
		Key:        testPrivateKey(t),
		SendCookie: true,
	})
	require.NoError(t, err)
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
	auth, err := New(&ToukaJWTMiddleware{
		Realm: "test",
		Key:   testPrivateKey(t),
	})
	require.NoError(t, err)
	handler := toukaHandler(auth)
	r := gofight.New()

	token := makeTokenWithClaims(t, testPrivateKey(t), jwtlib.MapClaims{
		"identity": "admin",
		"exp":      time.Now().Add(-time.Hour).Unix(),
	})

	r.GET("/auth/hello").SetHeader(gofight.H{"Authorization": "Bearer " + token}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, 401, r.Code)
			assert.Contains(t, r.Body.String(), "token is expired")
		})
}

func TestParseTokenRejectsTamperedSignature(t *testing.T) {
	mw, err := New(&ToukaJWTMiddleware{
		Realm: "test",
		Key:   testPrivateKey(t),
	})
	require.NoError(t, err)
	tampered := makeTokenString(t, testPrivateKey(t), "admin") + "tampered"
	w := httptest.NewRecorder()
	c, _ := touka.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/auth/hello", nil)
	req.Header.Set("Authorization", "Bearer "+tampered)
	c.Request = req
	_, err = mw.ParseToken(c)
	assert.Error(t, err)
	assert.Empty(t, GetToken(c))
}

func TestParseTokenRejectsWrongVerificationKey(t *testing.T) {
	wrongKey, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), secondarySeed)
	require.NoError(t, err)
	mw, err := New(&ToukaJWTMiddleware{
		Realm: "test",
		Key:   testPrivateKey(t),
		KeyFunc: func(token *jwtlib.Token) (any, error) {
			return wrongKey.PublicKey(), nil
		},
	})
	require.NoError(t, err)
	w := httptest.NewRecorder()
	c, _ := touka.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/auth/hello", nil)
	req.Header.Set("Authorization", "Bearer "+makeTokenString(t, testPrivateKey(t), "admin"))
	c.Request = req
	_, err = mw.ParseToken(c)
	assert.Error(t, err)
}

func TestRefreshHandlerRequiresRefreshToken(t *testing.T) {
	auth, err := New(&ToukaJWTMiddleware{
		Realm: "test",
		Key:   testPrivateKey(t),
	})
	require.NoError(t, err)
	handler := toukaHandler(auth)
	r := gofight.New()
	r.POST("/refresh").Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
		assert.Equal(t, http.StatusBadRequest, r.Code)
		assert.Contains(t, r.Body.String(), ErrMissingRefreshToken.Error())
	})
}

func TestRefreshHandlerRejectsQueryToken(t *testing.T) {
	auth, err := New(&ToukaJWTMiddleware{
		Realm: "test",
		Key:   testPrivateKey(t),
	})
	require.NoError(t, err)
	handler := toukaHandler(auth)
	r := gofight.New()
	r.POST("/refresh").SetQuery(gofight.H{"refresh_token": "query-token"}).Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
		assert.Equal(t, http.StatusBadRequest, r.Code)
		assert.Contains(t, r.Body.String(), ErrMissingRefreshToken.Error())
	})
}

func TestTokenGeneratorStoreFailure(t *testing.T) {
	mw, err := New(&ToukaJWTMiddleware{
		Realm: "test",
		Key:   testPrivateKey(t),
	})
	require.NoError(t, err)
	mw.TokenStore = &failingCoreStore{}
	_, err = mw.TokenGenerator(t.Context(), "admin")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "set failed")
}

type failingCoreStore struct{}

func (f *failingCoreStore) Set(ctx context.Context, token string, userData any, expiry time.Time) error {
	return errors.New("set failed")
}

func (f *failingCoreStore) Get(ctx context.Context, token string) (any, error) {
	return nil, core.ErrRefreshTokenNotFound
}

func (f *failingCoreStore) Delete(ctx context.Context, token string) error {
	return nil
}

func (f *failingCoreStore) Cleanup(ctx context.Context) (int, error) {
	return 0, nil
}

func (f *failingCoreStore) Count(ctx context.Context) (int, error) {
	return 0, nil
}

func TestHTTPStatusMessageFunc(t *testing.T) {
	customErr := errors.New("custom error")
	auth, err := New(&ToukaJWTMiddleware{
		Realm: "test",
		Key:   testPrivateKey(t),
		HTTPStatusMessageFunc: func(e error, c *touka.Context) string {
			if e == customErr {
				return "CUSTOM MESSAGE"
			}
			return e.Error()
		},
	})
	require.NoError(t, err)
	msg := auth.HTTPStatusMessageFunc(customErr, nil)
	assert.Equal(t, "CUSTOM MESSAGE", msg)
}

type hs512TestHelper struct {
	secret []byte
}

func newHS512Helper() *hs512TestHelper {
	return &hs512TestHelper{secret: []byte("hs512-test-secret-key-that-is-long-enough-for-hmac-sha512")}
}

func (h *hs512TestHelper) makeToken(t *testing.T, username string) string {
	t.Helper()
	token := jwtlib.New(jwtlib.SigningMethodHS512)
	claims := token.Claims.(jwtlib.MapClaims)
	claims["identity"] = username
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	claims["orig_iat"] = time.Now().Unix()
	s, err := token.SignedString(h.secret)
	require.NoError(t, err)
	return s
}

func (h *hs512TestHelper) makeTokenWithClaims(t *testing.T, claims jwtlib.MapClaims) string {
	t.Helper()
	token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS512, claims)
	s, err := token.SignedString(h.secret)
	require.NoError(t, err)
	return s
}

func (h *hs512TestHelper) middleware() *ToukaJWTMiddleware {
	return &ToukaJWTMiddleware{
		Realm:            "hs512-test",
		SigningAlgorithm: SigningAlgorithmHS512,
		Key:              h.secret,
		Authenticator: func(c *touka.Context) (any, error) {
			return "admin", nil
		},
		PayloadFunc: func(data any) MapClaims {
			return MapClaims{"identity": data}
		},
	}
}

func TestHS512AlgorithmInterfaceInit(t *testing.T) {
	alg, ok := LookupAlgorithm(SigningAlgorithmHS512)
	require.True(t, ok, "HS512 algorithm should be registered")
	assert.Equal(t, SigningAlgorithmHS512, alg.Alg())
	assert.NotNil(t, alg.SigningMethod())
	assert.Equal(t, jwtlib.SigningMethodHS512.Alg(), alg.Alg())
}

func TestHS512AlgorithmLoadSigningKey(t *testing.T) {
	alg, _ := LookupAlgorithm(SigningAlgorithmHS512)
	key, err := alg.LoadSigningKey([]byte("test-secret"))
	require.NoError(t, err)
	assert.Equal(t, []byte("test-secret"), key)
}

func TestHS512AlgorithmLoadSigningKeyEmpty(t *testing.T) {
	alg, _ := LookupAlgorithm(SigningAlgorithmHS512)
	_, err := alg.LoadSigningKey([]byte{})
	assert.Error(t, err)
}

func TestHS512AlgorithmLoadVerificationKey(t *testing.T) {
	alg, _ := LookupAlgorithm(SigningAlgorithmHS512)
	key, err := alg.LoadVerificationKey([]byte("test-secret"))
	require.NoError(t, err)
	assert.Equal(t, []byte("test-secret"), key)
}

func TestHS512AlgorithmVerificationKeyFromSigningKey(t *testing.T) {
	alg, _ := LookupAlgorithm(SigningAlgorithmHS512)
	signingKey := []byte("shared-secret")
	verifyKey, err := alg.VerificationKeyFromSigningKey(signingKey)
	require.NoError(t, err)
	assert.Equal(t, signingKey, verifyKey)
}

func TestHS512AlgorithmVerificationKeyFromSigningKeyWrongType(t *testing.T) {
	alg, _ := LookupAlgorithm(SigningAlgorithmHS512)
	_, err := alg.VerificationKeyFromSigningKey("not-a-byte-slice")
	assert.Error(t, err)
}

func TestHS512MiddlewareInit(t *testing.T) {
	h := newHS512Helper()
	auth, err := New(h.middleware())
	require.NoError(t, err)
	assert.Equal(t, SigningAlgorithmHS512, auth.SigningAlgorithm)
	assert.NotNil(t, auth.algorithm)
	assert.NotNil(t, auth.Key)
	assert.NotNil(t, auth.verifyKey)
	assert.Equal(t, h.secret, auth.verifyKey)
}

func TestHS512MiddlewareInitWithPrivKeyBytes(t *testing.T) {
	h := newHS512Helper()
	auth, err := New(&ToukaJWTMiddleware{
		Realm:            "test",
		SigningAlgorithm: SigningAlgorithmHS512,
		PrivKeyBytes:     h.secret,
	})
	require.NoError(t, err)
	assert.NotNil(t, auth.Key)
	assert.Equal(t, h.secret, auth.Key)
	assert.NotNil(t, auth.verifyKey)
}

func TestHS512MiddlewareInitVerifyOnly(t *testing.T) {
	h := newHS512Helper()
	auth, err := New(&ToukaJWTMiddleware{
		Realm:            "test",
		SigningAlgorithm: SigningAlgorithmHS512,
		PubKeyBytes:      h.secret,
	})
	require.NoError(t, err)
	assert.Nil(t, auth.Key)
	assert.Equal(t, h.secret, auth.verifyKey)
}

func TestHS512MiddlewareInitRejectUnknownAlgorithm(t *testing.T) {
	_, err := New(&ToukaJWTMiddleware{
		Realm:            "test",
		SigningAlgorithm: "HS384",
		Key:              []byte("secret"),
	})
	assert.ErrorIs(t, err, ErrInvalidSigningAlgorithm)
}

func TestHS512TokenSigningAndVerification(t *testing.T) {
	h := newHS512Helper()
	auth, err := New(h.middleware())
	require.NoError(t, err)

	token := h.makeToken(t, "admin")
	w := httptest.NewRecorder()
	c, _ := touka.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/auth/hello", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	c.Request = req

	parsed, err := auth.ParseToken(c)
	require.NoError(t, err)
	assert.True(t, parsed.Valid)
	claims := ExtractClaimsFromToken(parsed)
	assert.Equal(t, "admin", claims["identity"])
}

func TestHS512TokenRejectsWrongKey(t *testing.T) {
	h := newHS512Helper()
	wrongSecret := []byte("wrong-secret-key-that-is-long-enough-for-hmac-sha512")
	auth, err := New(h.middleware())
	require.NoError(t, err)

	wrongToken := jwtlib.New(jwtlib.SigningMethodHS512)
	claims := wrongToken.Claims.(jwtlib.MapClaims)
	claims["identity"] = "admin"
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	wrongTokenStr, _ := wrongToken.SignedString(wrongSecret)
	w := httptest.NewRecorder()
	c, _ := touka.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/auth/hello", nil)
	req.Header.Set("Authorization", "Bearer "+wrongTokenStr)
	c.Request = req

	_, err = auth.ParseToken(c)
	assert.Error(t, err)
}

func TestHS512TokenRejectsTamperedSignature(t *testing.T) {
	h := newHS512Helper()
	auth, err := New(h.middleware())
	require.NoError(t, err)

	tampered := h.makeToken(t, "admin") + "x"
	w := httptest.NewRecorder()
	c, _ := touka.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/auth/hello", nil)
	req.Header.Set("Authorization", "Bearer "+tampered)
	c.Request = req

	_, err = auth.ParseToken(c)
	assert.Error(t, err)
}

func TestHS512DualTokenFlow(t *testing.T) {
	h := newHS512Helper()
	auth, err := New(h.middleware())
	require.NoError(t, err)
	handler := toukaHandlerForAlgorithm(auth)
	r := gofight.New()

	var accessToken, refreshToken string

	r.POST("/login").Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
		assert.Equal(t, 200, r.Code)
		accessToken = gjson.Get(r.Body.String(), "access_token").String()
		refreshToken = gjson.Get(r.Body.String(), "refresh_token").String()
		assert.NotEmpty(t, accessToken)
		assert.NotEmpty(t, refreshToken)
	})

	r.GET("/auth/hello").SetHeader(gofight.H{"Authorization": "Bearer " + accessToken}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, 200, r.Code)
			assert.Equal(t, "admin", gjson.Get(r.Body.String(), "userID").String())
		})

	time.Sleep(time.Second)
	r.POST("/refresh").SetForm(gofight.H{"refresh_token": refreshToken}).Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
		assert.Equal(t, 200, r.Code)
		newAccessToken := gjson.Get(r.Body.String(), "access_token").String()
		assert.NotEmpty(t, newAccessToken)
		assert.NotEqual(t, accessToken, newAccessToken)
	})

	r.POST("/refresh").SetForm(gofight.H{"refresh_token": refreshToken}).Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
		assert.Equal(t, 401, r.Code)
	})
}

func TestHS512ExpiredToken(t *testing.T) {
	h := newHS512Helper()
	auth, err := New(h.middleware())
	require.NoError(t, err)
	handler := toukaHandlerForAlgorithm(auth)
	r := gofight.New()

	token := h.makeTokenWithClaims(t, jwtlib.MapClaims{
		"identity": "admin",
		"exp":      time.Now().Add(-time.Hour).Unix(),
	})

	r.GET("/auth/hello").SetHeader(gofight.H{"Authorization": "Bearer " + token}).
		Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
			assert.Equal(t, 401, r.Code)
			assert.Contains(t, r.Body.String(), "token is expired")
		})
}

func TestHS512KeyFuncOverridesVerificationKey(t *testing.T) {
	h := newHS512Helper()
	wrongSecret := []byte("wrong-secret-key-that-is-long-enough-for-hmac-sha512")
	auth, err := New(&ToukaJWTMiddleware{
		Realm:            "hs512-test",
		SigningAlgorithm: SigningAlgorithmHS512,
		Key:              h.secret,
		KeyFunc: func(token *jwtlib.Token) (any, error) {
			return wrongSecret, nil
		},
		Authenticator: func(c *touka.Context) (any, error) {
			return "admin", nil
		},
		PayloadFunc: func(data any) MapClaims {
			return MapClaims{"identity": data}
		},
	})
	require.NoError(t, err)

	w := httptest.NewRecorder()
	c, _ := touka.CreateTestContext(w)
	token := h.makeToken(t, "admin")
	req := httptest.NewRequest(http.MethodGet, "/auth/hello", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	c.Request = req

	_, err = auth.ParseToken(c)
	assert.Error(t, err)
}

func TestHS512VerifyOnlyMode(t *testing.T) {
	h := newHS512Helper()
	auth, err := New(&ToukaJWTMiddleware{
		Realm:            "test",
		SigningAlgorithm: SigningAlgorithmHS512,
		PubKeyBytes:      h.secret,
	})
	require.NoError(t, err)
	assert.Nil(t, auth.Key)
	assert.Equal(t, h.secret, auth.verifyKey)

	token := h.makeToken(t, "admin")
	w := httptest.NewRecorder()
	c, _ := touka.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/auth/hello", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	c.Request = req

	parsed, err := auth.ParseToken(c)
	require.NoError(t, err)
	assert.True(t, parsed.Valid)

	_, err = auth.TokenGenerator(t.Context(), "admin")
	assert.ErrorIs(t, err, ErrMissingPrivateKey)
}

func TestHS512LoginAndLogout(t *testing.T) {
	h := newHS512Helper()
	auth, err := New(h.middleware())
	require.NoError(t, err)
	handler := toukaHandlerForAlgorithm(auth)
	r := gofight.New()

	r.POST("/login").Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
		assert.Equal(t, 200, r.Code)
		assert.NotEmpty(t, gjson.Get(r.Body.String(), "access_token").String())
		assert.NotEmpty(t, gjson.Get(r.Body.String(), "refresh_token").String())
	})
}

func TestHS512RefreshRequiresToken(t *testing.T) {
	h := newHS512Helper()
	auth, err := New(h.middleware())
	require.NoError(t, err)
	handler := toukaHandlerForAlgorithm(auth)
	r := gofight.New()

	r.POST("/refresh").Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
		assert.Equal(t, http.StatusBadRequest, r.Code)
		assert.Contains(t, r.Body.String(), ErrMissingRefreshToken.Error())
	})
}

func TestHS512RefreshRejectsQueryToken(t *testing.T) {
	h := newHS512Helper()
	auth, err := New(h.middleware())
	require.NoError(t, err)
	handler := toukaHandlerForAlgorithm(auth)
	r := gofight.New()

	r.POST("/refresh").SetQuery(gofight.H{"refresh_token": "some-token"}).Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
		assert.Equal(t, http.StatusBadRequest, r.Code)
	})
}

func TestRefreshHandlerRejectsTokenStoreWithoutAtomicRotate(t *testing.T) {
	h := newHS512Helper()
	auth, err := New(h.middleware())
	require.NoError(t, err)
	store := &nonRotatorStore{tokens: map[string]any{"old-refresh": "admin"}}
	auth.TokenStore = store
	handler := toukaHandlerForAlgorithm(auth)
	r := gofight.New()
	r.POST("/refresh").SetForm(gofight.H{"refresh_token": "old-refresh"}).Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
		assert.Equal(t, http.StatusInternalServerError, r.Code)
		assert.Contains(t, r.Body.String(), ErrUnsafeRefreshRotation.Error())
	})
	_, oldStillPresent := store.tokens["old-refresh"]
	assert.True(t, oldStillPresent, "old refresh token should remain untouched when atomic rotate is unavailable")
	_, newPresent := store.tokens["new-refresh"]
	assert.False(t, newPresent)
}

func TestRefreshHandlerUsesAtomicRotateWhenAvailable(t *testing.T) {
	h := newHS512Helper()
	auth, err := New(h.middleware())
	require.NoError(t, err)
	store := &recordingRotatorStore{tokens: map[string]any{"old-refresh": "admin"}}
	auth.TokenStore = store
	handler := toukaHandlerForAlgorithm(auth)
	r := gofight.New()
	r.POST("/refresh").SetForm(gofight.H{"refresh_token": "old-refresh"}).Run(handler, func(r gofight.HTTPResponse, rq gofight.HTTPRequest) {
		assert.Equal(t, http.StatusOK, r.Code)
	})
	assert.Len(t, store.rotateCalls, 1)
	assert.Equal(t, "old-refresh", store.rotateCalls[0].oldToken)
	assert.NotEmpty(t, store.rotateCalls[0].newToken)
	_, oldStillPresent := store.tokens["old-refresh"]
	assert.False(t, oldStillPresent)
	_, newPresent := store.tokens[store.rotateCalls[0].newToken]
	assert.True(t, newPresent)
}

func TestRotateRefreshTokenRejectsTokenStoreWithoutAtomicRotate(t *testing.T) {
	auth, err := New(&ToukaJWTMiddleware{
		Realm: "test",
		Key:   testPrivateKey(t),
	})
	require.NoError(t, err)

	store := &nonRotatorStore{tokens: map[string]any{"old-refresh": "admin"}}
	auth.TokenStore = store

	err = auth.rotateRefreshToken(context.Background(), "old-refresh", "new-refresh", "admin")
	assert.ErrorIs(t, err, ErrUnsafeRefreshRotation)
	_, err = store.Get(context.Background(), "old-refresh")
	require.NoError(t, err)
	_, err = store.Get(context.Background(), "new-refresh")
	assert.ErrorIs(t, err, core.ErrRefreshTokenNotFound)
}

type nonRotatorStore struct {
	tokens map[string]any
}

func (f *nonRotatorStore) Set(ctx context.Context, token string, userData any, expiry time.Time) error {
	f.tokens[token] = userData
	return nil
}

func (f *nonRotatorStore) Get(ctx context.Context, token string) (any, error) {
	data, ok := f.tokens[token]
	if !ok {
		return nil, core.ErrRefreshTokenNotFound
	}
	return data, nil
}

func (f *nonRotatorStore) Delete(ctx context.Context, token string) error {
	delete(f.tokens, token)
	return nil
}

func (f *nonRotatorStore) Cleanup(ctx context.Context) (int, error) {
	return 0, nil
}

func (f *nonRotatorStore) Count(ctx context.Context) (int, error) {
	return 0, nil
}

type rotateCall struct {
	oldToken string
	newToken string
}

type recordingRotatorStore struct {
	tokens      map[string]any
	rotateCalls []rotateCall
}

func (r *recordingRotatorStore) Set(ctx context.Context, token string, userData any, expiry time.Time) error {
	r.tokens[token] = userData
	return nil
}

func (r *recordingRotatorStore) Get(ctx context.Context, token string) (any, error) {
	data, ok := r.tokens[token]
	if !ok {
		return nil, core.ErrRefreshTokenNotFound
	}
	return data, nil
}

func (r *recordingRotatorStore) Delete(ctx context.Context, token string) error {
	delete(r.tokens, token)
	return nil
}

func (r *recordingRotatorStore) Rotate(ctx context.Context, oldToken, newToken string, userData any, expiry time.Time) error {
	r.rotateCalls = append(r.rotateCalls, rotateCall{oldToken: oldToken, newToken: newToken})
	delete(r.tokens, oldToken)
	r.tokens[newToken] = userData
	return nil
}

func (r *recordingRotatorStore) Cleanup(ctx context.Context) (int, error) {
	return 0, nil
}

func (r *recordingRotatorStore) Count(ctx context.Context) (int, error) {
	return len(r.tokens), nil
}

type revokeCall struct {
	tokens []string
}

type recordingRevokerStore struct {
	tokens      map[string]any
	revokeCalls []revokeCall
	deleteCalls []string
	revokeErr   error
}

func (r *recordingRevokerStore) Set(ctx context.Context, token string, userData any, expiry time.Time) error {
	r.tokens[token] = userData
	return nil
}

func (r *recordingRevokerStore) Get(ctx context.Context, token string) (any, error) {
	data, ok := r.tokens[token]
	if !ok {
		return nil, core.ErrRefreshTokenNotFound
	}
	return data, nil
}

func (r *recordingRevokerStore) Delete(ctx context.Context, token string) error {
	r.deleteCalls = append(r.deleteCalls, token)
	delete(r.tokens, token)
	return nil
}

func (r *recordingRevokerStore) Revoke(ctx context.Context, tokens []string) error {
	cloned := append([]string(nil), tokens...)
	r.revokeCalls = append(r.revokeCalls, revokeCall{tokens: cloned})
	if r.revokeErr != nil {
		return r.revokeErr
	}
	for _, token := range tokens {
		delete(r.tokens, token)
	}
	return nil
}

func (r *recordingRevokerStore) Cleanup(ctx context.Context) (int, error) {
	return 0, nil
}

func (r *recordingRevokerStore) Count(ctx context.Context) (int, error) {
	return len(r.tokens), nil
}

func TestLogoutHandlerUsesAtomicRevokeWhenAvailable(t *testing.T) {
	auth, err := New(&ToukaJWTMiddleware{
		Realm: "test",
		Key:   testPrivateKey(t),
	})
	require.NoError(t, err)

	store := &recordingRevokerStore{tokens: map[string]any{
		"r1": "admin",
		"r2": "admin",
		"r3": "admin",
	}}
	auth.TokenStore = store

	now := time.Now()
	setRefreshTokenSuccessor("r1", "r2", now.Add(time.Minute), now)
	setRefreshTokenSuccessor("r2", "r3", now.Add(time.Minute), now)

	w := httptest.NewRecorder()
	c, _ := touka.CreateTestContext(w)
	form := strings.NewReader("refresh_token=r1")
	req := httptest.NewRequest(http.MethodPost, "/logout", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.Request = req

	auth.LogoutHandler(c)

	assert.Len(t, store.revokeCalls, 1)
	assert.Equal(t, []string{"r1", "r2", "r3"}, store.revokeCalls[0].tokens)
	assert.Empty(t, store.deleteCalls)
	for _, token := range []string{"r1", "r2", "r3"} {
		_, err := store.Get(context.Background(), token)
		assert.ErrorIs(t, err, core.ErrRefreshTokenNotFound)
		assert.Equal(t, "", nextRefreshToken(token, time.Now()))
	}
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestLogoutHandlerRevokesKnownSuccessorsPastExpiredLink(t *testing.T) {
	auth, err := New(&ToukaJWTMiddleware{
		Realm: "test",
		Key:   testPrivateKey(t),
	})
	require.NoError(t, err)

	store := &recordingRevokerStore{tokens: map[string]any{
		"r1": "admin",
		"r2": "admin",
		"r3": "admin",
	}}
	auth.TokenStore = store

	now := time.Now()
	setRefreshTokenSuccessor("r1", "r2", now.Add(-time.Second), now)
	setRefreshTokenSuccessor("r2", "r3", now.Add(time.Minute), now)

	w := httptest.NewRecorder()
	c, _ := touka.CreateTestContext(w)
	form := strings.NewReader("refresh_token=r1")
	req := httptest.NewRequest(http.MethodPost, "/logout", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.Request = req

	auth.LogoutHandler(c)

	assert.Len(t, store.revokeCalls, 1)
	assert.Equal(t, []string{"r1", "r2", "r3"}, store.revokeCalls[0].tokens)
	for _, token := range []string{"r1", "r2", "r3"} {
		_, err := store.Get(context.Background(), token)
		assert.ErrorIs(t, err, core.ErrRefreshTokenNotFound)
		assert.Equal(t, "", logoutSuccessorToken(token))
	}
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestLogoutHandlerKeepsIdempotentBehaviorForAtomicRevoke(t *testing.T) {
	auth, err := New(&ToukaJWTMiddleware{
		Realm: "test",
		Key:   testPrivateKey(t),
	})
	require.NoError(t, err)

	store := &recordingRevokerStore{
		tokens:    map[string]any{"r1": "admin"},
		revokeErr: core.ErrRefreshTokenNotFound,
	}
	auth.TokenStore = store

	w := httptest.NewRecorder()
	c, _ := touka.CreateTestContext(w)
	form := strings.NewReader("refresh_token=r1")
	req := httptest.NewRequest(http.MethodPost, "/logout", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.Request = req

	auth.LogoutHandler(c)

	assert.Len(t, store.revokeCalls, 1)
	assert.Equal(t, http.StatusOK, w.Code)
}

func toukaHandlerForAlgorithm(auth *ToukaJWTMiddleware) *touka.Engine {
	r := touka.New()
	r.POST("/login", auth.LoginHandler)
	r.POST("/logout", auth.LogoutHandler)
	r.POST("/refresh", auth.RefreshHandler)

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
