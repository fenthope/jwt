package jwt

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fenthope/jwt/core"
	"github.com/fenthope/jwt/store"
	"github.com/golang-jwt/jwt/v5"
	"github.com/infinite-iroha/touka"
)

type MapClaims jwt.MapClaims

type tokenLookupSource struct {
	kind string
	name string
}

type tokenStoreRefreshTokenManager struct {
	mw *ToukaJWTMiddleware
}

type refreshTokenLockEntry struct {
	mu   sync.Mutex
	refs int
}

type refreshTokenChainEntry struct {
	next   string
	expiry time.Time
}

type ToukaJWTMiddleware struct {
	Realm string
	// Defaults to the built-in ML-DSA-65 implementation.
	SigningAlgorithm string
	// Key signs access tokens. Its concrete type depends on SigningAlgorithm.
	Key         any
	KeyFunc     func(token *jwt.Token) (any, error)
	Timeout     time.Duration
	TimeoutFunc func(data any) time.Duration

	MaxRefresh          time.Duration
	RefreshTokenTimeout time.Duration

	Authenticator         func(c *touka.Context) (any, error)
	Authorizator          func(data any, c *touka.Context) bool
	LoginResponse         func(c *touka.Context, code int, token *core.Token)
	LogoutResponse        func(c *touka.Context, code int)
	RefreshResponse       func(c *touka.Context, code int, token *core.Token)
	Unauthorized          func(c *touka.Context, code int, message string)
	HTTPStatusMessageFunc func(e error, c *touka.Context) string

	IdentityKey   string
	TokenLookup   string
	TokenHeadName string
	TimeFunc      func() time.Time

	DisabledAbort  bool
	ExpField       string
	SendCookie     bool
	CookieName     string
	CookieMaxAge   time.Duration
	CookieDomain   string
	SecureCookie   bool
	CookieHTTPOnly bool
	CookieSameSite http.SameSite

	RefreshTokenCookieName string

	RefreshTokenSecureCookie   bool
	RefreshTokenCookieHTTPOnly bool

	PayloadFunc       func(data any) MapClaims
	IdentityHandler   func(c *touka.Context) any
	ParseOptions      []jwt.ParserOption
	SendAuthorization bool

	// PrivKeyFile points to the algorithm-specific signing-key input bytes.
	PrivKeyFile string
	// PrivKeyBytes contains the algorithm-specific signing-key input bytes.
	PrivKeyBytes []byte
	// PubKeyFile points to the algorithm-specific verification-key input bytes.
	PubKeyFile string
	// PubKeyBytes contains the algorithm-specific verification-key input bytes.
	PubKeyBytes []byte

	// RefreshTokenManager owns the higher-level refresh lifecycle. When set, it
	// is used for login persistence, refresh rotation, and logout revocation.
	RefreshTokenManager core.RefreshTokenManager
	// TokenStore remains the low-level compatibility path used when
	// RefreshTokenManager is nil.
	TokenStore core.TokenStore

	algorithm     Algorithm
	verifyKey     any
	inMemoryStore *store.InMemoryRefreshTokenStore
	tokenSources  []tokenLookupSource
}

var (
	ErrMissingRealm             = errors.New("realm is missing")
	ErrMissingSecretKey         = errors.New("secret key is missing")
	ErrForbidden                = errors.New("you don't have permission to access")
	ErrMissingAuthenticatorFunc = errors.New("authenticator function is missing")
	ErrMissingExpField          = errors.New("missing exp field")
	ErrWrongFormatOfExp         = errors.New("wrong format of exp field")
	ErrInvalidSigningAlgorithm  = errors.New("invalid signing algorithm")
	ErrInvalidPrivKey           = errors.New("invalid private key")
	ErrInvalidPubKey            = errors.New("invalid public key")
	ErrEmptyAuthHeader          = errors.New("auth header is empty")
	ErrInvalidAuthHeader        = errors.New("auth header is invalid")
	ErrEmptyQueryToken          = errors.New("query token is empty")
	ErrEmptyCookieToken         = errors.New("cookie token is empty")
	ErrEmptyParamToken          = errors.New("parameter token is empty")
	ErrFailedAuthentication     = errors.New("incorrect Username or Password")
	ErrMissingLoginValues       = errors.New("missing Username or Password")
	ErrFailedTokenCreation      = errors.New("failed to create token")
	ErrMissingPrivateKey        = errors.New("private key is missing")
	ErrExpiredToken             = errors.New("token is expired")
	ErrMissingRefreshToken      = errors.New("refresh token is missing")
	ErrUnsafeRefreshRotation    = errors.New("token store must implement RefreshTokenRotator for refresh rotation")
	ErrInvalidTokenLookup       = errors.New("token lookup is invalid")

	refreshTokenLocksMu sync.Mutex
	refreshTokenLocks   = map[string]*refreshTokenLockEntry{}

	refreshTokenChainMu      sync.Mutex
	refreshTokenChain        = map[string]refreshTokenChainEntry{}
	refreshTokenChainSweeps  int
	refreshTokenChainSweepAt = 64
)

func New(mw *ToukaJWTMiddleware) (*ToukaJWTMiddleware, error) {
	if err := mw.MiddlewareInit(); err != nil {
		return nil, err
	}
	return mw, nil
}

func (mw *ToukaJWTMiddleware) MiddlewareInit() error {
	if mw.TokenLookup == "" {
		mw.TokenLookup = "header:Authorization"
	}
	if mw.SigningAlgorithm == "" {
		mw.SigningAlgorithm = SigningAlgorithmMLDSA65
	}
	if mw.Timeout == 0 {
		mw.Timeout = time.Hour
	}
	if mw.TimeFunc == nil {
		mw.TimeFunc = time.Now
	}
	if mw.TimeoutFunc == nil {
		mw.TimeoutFunc = func(data any) time.Duration { return mw.Timeout }
	}
	if mw.IdentityKey == "" {
		mw.IdentityKey = "identity"
	}
	if mw.TokenHeadName == "" {
		mw.TokenHeadName = "Bearer"
	}
	if mw.ExpField == "" {
		mw.ExpField = "exp"
	}
	if mw.CookieName == "" {
		mw.CookieName = "jwt"
	}
	if mw.RefreshTokenCookieName == "" {
		mw.RefreshTokenCookieName = "refresh_token"
	}
	if mw.SendCookie {
		mw.RefreshTokenSecureCookie = true
		mw.RefreshTokenCookieHTTPOnly = true
	}
	if mw.RefreshTokenTimeout == 0 {
		if mw.MaxRefresh != 0 {
			mw.RefreshTokenTimeout = mw.MaxRefresh
		} else {
			mw.RefreshTokenTimeout = time.Hour * 24 * 7
		}
	}

	if mw.Authorizator == nil {
		mw.Authorizator = func(data any, c *touka.Context) bool { return true }
	}
	if mw.Unauthorized == nil {
		mw.Unauthorized = func(c *touka.Context, code int, message string) {
			c.JSON(code, touka.H{"code": code, "message": message})
		}
	}
	if mw.LoginResponse == nil {
		mw.LoginResponse = func(c *touka.Context, code int, token *core.Token) {
			c.JSON(code, touka.H{
				"code":          code,
				"access_token":  token.AccessToken,
				"refresh_token": token.RefreshToken,
				"expire":        time.Unix(token.ExpiresAt, 0).Format(time.RFC3339),
			})
		}
	}
	if mw.LogoutResponse == nil {
		mw.LogoutResponse = func(c *touka.Context, code int) {
			c.JSON(code, touka.H{"code": code})
		}
	}
	if mw.RefreshResponse == nil {
		mw.RefreshResponse = func(c *touka.Context, code int, token *core.Token) {
			c.JSON(code, touka.H{
				"code":          code,
				"access_token":  token.AccessToken,
				"refresh_token": token.RefreshToken,
				"expire":        time.Unix(token.ExpiresAt, 0).Format(time.RFC3339),
			})
		}
	}
	if mw.IdentityHandler == nil {
		mw.IdentityHandler = func(c *touka.Context) any {
			claims := ExtractClaims(c)
			return claims[mw.IdentityKey]
		}
	}
	if mw.HTTPStatusMessageFunc == nil {
		mw.HTTPStatusMessageFunc = func(e error, c *touka.Context) string {
			if e == nil {
				return ""
			}
			return e.Error()
		}
	}

	if mw.TokenStore == nil && mw.RefreshTokenManager == nil {
		mw.inMemoryStore = store.NewInMemoryRefreshTokenStoreWithClock(mw.TimeFunc)
		mw.TokenStore = mw.inMemoryStore
	}

	sources, err := parseTokenLookupSources(mw.TokenLookup)
	if err != nil {
		return err
	}
	mw.tokenSources = sources

	if mw.Realm == "" {
		return ErrMissingRealm
	}
	alg, ok := LookupAlgorithm(mw.SigningAlgorithm)
	if !ok {
		return ErrInvalidSigningAlgorithm
	}
	mw.algorithm = alg
	if err := mw.readKeys(); err != nil {
		return err
	}
	if mw.Key == nil && mw.verifyKey == nil {
		return ErrMissingSecretKey
	}
	return nil
}

func (mw *ToukaJWTMiddleware) readKeys() error {
	hasPrivateKey := mw.Key != nil || len(mw.PrivKeyBytes) > 0 || mw.PrivKeyFile != ""
	hasPublicKey := mw.verifyKey != nil || len(mw.PubKeyBytes) > 0 || mw.PubKeyFile != ""

	if hasPrivateKey {
		if err := mw.privateKey(); err != nil {
			return err
		}
	}
	if hasPublicKey || mw.Key != nil {
		if err := mw.publicKey(); err != nil {
			return err
		}
	}
	return nil
}

func (mw *ToukaJWTMiddleware) privateKey() error {
	if mw.Key != nil {
		return nil
	}
	var keyData []byte
	if mw.PrivKeyFile == "" {
		if len(mw.PrivKeyBytes) > 0 {
			keyData = mw.PrivKeyBytes
		} else {
			return ErrInvalidPrivKey
		}
	} else {
		filecontent, err := os.ReadFile(mw.PrivKeyFile)
		if err != nil {
			return ErrInvalidPrivKey
		}
		keyData = filecontent
	}
	key, err := mw.algorithm.LoadSigningKey(keyData)
	if err != nil {
		return ErrInvalidPrivKey
	}
	mw.Key = key
	return nil
}

func (mw *ToukaJWTMiddleware) publicKey() error {
	if mw.verifyKey != nil {
		return nil
	}
	if len(mw.PubKeyBytes) == 0 && mw.PubKeyFile == "" {
		if mw.Key == nil {
			return ErrMissingSecretKey
		}
		verifyKey, err := mw.algorithm.VerificationKeyFromSigningKey(mw.Key)
		if err != nil {
			return ErrInvalidPubKey
		}
		mw.verifyKey = verifyKey
		return nil
	}
	var keyData []byte
	if mw.PubKeyFile == "" {
		if len(mw.PubKeyBytes) > 0 {
			keyData = mw.PubKeyBytes
		} else {
			return ErrMissingSecretKey
		}
	} else {
		filecontent, err := os.ReadFile(mw.PubKeyFile)
		if err != nil {
			return ErrInvalidPubKey
		}
		keyData = filecontent
	}
	key, err := mw.algorithm.LoadVerificationKey(keyData)
	if err != nil {
		return ErrInvalidPubKey
	}
	mw.verifyKey = key
	return nil
}

func (mw *ToukaJWTMiddleware) MiddlewareFunc() touka.HandlerFunc {
	return func(c *touka.Context) {
		if mw == nil {
			return
		}
		mw.middlewareImpl(c)
	}
}

func (mw *ToukaJWTMiddleware) middlewareImpl(c *touka.Context) {
	claims, err := mw.GetClaimsFromJWT(c)
	if err != nil {
		mw.handleTokenError(c, err)
		return
	}
	if err := mw.validateClaimsExpiry(claims); err != nil {
		if errors.Is(err, ErrMissingExpField) || errors.Is(err, ErrWrongFormatOfExp) {
			mw.unauthorized(c, http.StatusBadRequest, mw.HTTPStatusMessageFunc(err, c))
			return
		}
		mw.handleTokenError(c, err)
		return
	}
	c.Set("JWT_PAYLOAD", claims)
	identity := mw.IdentityHandler(c)
	if identity != nil {
		c.Set(mw.IdentityKey, identity)
	}
	if !mw.Authorizator(identity, c) {
		mw.unauthorized(c, http.StatusForbidden, mw.HTTPStatusMessageFunc(ErrForbidden, c))
		return
	}
	c.Next()
}

func (mw *ToukaJWTMiddleware) GetClaimsFromJWT(c *touka.Context) (jwt.MapClaims, error) {
	token, err := mw.ParseToken(c)
	if err != nil {
		return nil, err
	}
	if mw.SendAuthorization {
		if v, ok := c.Get("JWT_TOKEN"); ok {
			c.SetHeader("Authorization", mw.TokenHeadName+" "+v.(string))
		}
	}
	return token.Claims.(jwt.MapClaims), nil
}

func (mw *ToukaJWTMiddleware) LoginHandler(c *touka.Context) {
	if mw.Authenticator == nil {
		mw.unauthorized(c, http.StatusInternalServerError, mw.HTTPStatusMessageFunc(ErrMissingAuthenticatorFunc, c))
		return
	}
	data, err := mw.Authenticator(c)
	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(err, c))
		return
	}
	tokenPair, err := mw.TokenGenerator(c.Request.Context(), data)
	if err != nil {
		if errors.Is(err, ErrMissingPrivateKey) {
			mw.unauthorized(c, http.StatusInternalServerError, mw.HTTPStatusMessageFunc(err, c))
			return
		}
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrFailedTokenCreation, c))
		return
	}
	mw.setAccessTokenCookie(c, tokenPair.AccessToken, tokenPair.ExpiresAt)
	mw.SetRefreshTokenCookie(c, tokenPair.RefreshToken, tokenPair.RefreshExpiresAt)
	mw.LoginResponse(c, http.StatusOK, tokenPair)
}

func (mw *ToukaJWTMiddleware) LogoutHandler(c *touka.Context) {
	refreshToken := mw.extractRefreshToken(c)
	if refreshToken != "" {
		if err := mw.revokeRefreshToken(c.Request.Context(), refreshToken); err != nil {
			mw.unauthorized(c, http.StatusInternalServerError, mw.HTTPStatusMessageFunc(err, c))
			return
		}
	}
	if mw.SendCookie {
		mw.writeCookie(c, mw.CookieName, "", -1, mw.SecureCookie, mw.CookieHTTPOnly)
		mw.writeCookie(c, mw.RefreshTokenCookieName, "", -1, mw.RefreshTokenSecureCookie, mw.RefreshTokenCookieHTTPOnly)
	}
	mw.LogoutResponse(c, http.StatusOK)
}

func (mw *ToukaJWTMiddleware) RefreshHandler(c *touka.Context) {
	refreshToken := mw.extractRefreshToken(c)
	if refreshToken == "" {
		mw.unauthorized(c, http.StatusBadRequest, mw.HTTPStatusMessageFunc(ErrMissingRefreshToken, c))
		return
	}
	userData, err := mw.refreshTokenManager().Lookup(c.Request.Context(), refreshToken)
	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(err, c))
		return
	}
	userData = mw.normalizeRefreshTokenState(userData)
	if err := mw.validateRefreshTokenState(userData); err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(err, c))
		return
	}
	tokenPair, err := mw.generateTokenPair(mw.refreshTokenUserData(userData))
	if err != nil {
		mw.unauthorized(c, http.StatusInternalServerError, mw.HTTPStatusMessageFunc(err, c))
		return
	}
	tokenPair.RefreshExpiresAt = mw.refreshTokenExpiry(userData).Unix()
	if err := mw.rotateRefreshToken(c.Request.Context(), refreshToken, tokenPair.RefreshToken, userData); err != nil {
		if errors.Is(err, core.ErrRefreshTokenExpired) || errors.Is(err, core.ErrRefreshTokenNotFound) {
			mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(err, c))
			return
		}
		mw.unauthorized(c, http.StatusInternalServerError, mw.HTTPStatusMessageFunc(err, c))
		return
	}
	if mw.SendCookie {
		mw.setAccessTokenCookie(c, tokenPair.AccessToken, tokenPair.ExpiresAt)
		mw.SetRefreshTokenCookie(c, tokenPair.RefreshToken, tokenPair.RefreshExpiresAt)
	}
	mw.RefreshResponse(c, http.StatusOK, tokenPair)
}

func (mw *ToukaJWTMiddleware) TokenGenerator(ctx context.Context, data any) (*core.Token, error) {
	tokenPair, err := mw.generateTokenPair(data)
	if err != nil {
		return nil, err
	}
	storedToken := mw.newRefreshTokenState(data)
	tokenPair.RefreshExpiresAt = mw.refreshTokenExpiry(storedToken).Unix()
	err = mw.refreshTokenManager().Store(ctx, tokenPair.RefreshToken, storedToken, time.Unix(tokenPair.RefreshExpiresAt, 0))
	if err != nil {
		return nil, err
	}
	return tokenPair, nil
}

func (mw *ToukaJWTMiddleware) generateTokenPair(data any) (*core.Token, error) {
	if mw.Key == nil {
		return nil, ErrMissingPrivateKey
	}
	token := jwt.New(mw.algorithm.SigningMethod())
	claims := token.Claims.(jwt.MapClaims)
	if mw.PayloadFunc != nil {
		for k, v := range mw.PayloadFunc(data) {
			claims[k] = v
		}
	}
	expire := mw.TimeFunc().Add(mw.TimeoutFunc(data))
	claims[mw.ExpField] = expire.Unix()
	claims["orig_iat"] = mw.TimeFunc().Unix()
	accessToken, err := mw.signedString(token)
	if err != nil {
		return nil, err
	}

	refreshToken, err := mw.generateRefreshToken()
	if err != nil {
		return nil, err
	}

	return &core.Token{
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		ExpiresAt:        expire.Unix(),
		CreatedAt:        mw.TimeFunc().Unix(),
		TokenType:        "Bearer",
		RefreshExpiresAt: mw.refreshTokenExpiry(mw.newRefreshTokenState(data)).Unix(),
	}, nil
}

func (mw *ToukaJWTMiddleware) rotateRefreshToken(ctx context.Context, oldToken, newToken string, userData any) error {
	userData = mw.normalizeRefreshTokenState(userData)
	return mw.refreshTokenManager().Rotate(ctx, oldToken, newToken, userData, mw.refreshTokenExpiry(userData))
}

func (mw *ToukaJWTMiddleware) revokeRefreshToken(ctx context.Context, token string) error {
	err := mw.refreshTokenManager().Revoke(ctx, token)
	if err == nil || errors.Is(err, core.ErrRefreshTokenNotFound) || errors.Is(err, core.ErrRefreshTokenExpired) {
		return nil
	}
	return err
}

func (mw *ToukaJWTMiddleware) revokeRefreshTokenChain(ctx context.Context, tokens []string) error {
	if len(tokens) == 0 {
		return nil
	}
	if revoker, ok := mw.TokenStore.(core.RefreshTokenRevoker); ok {
		err := revoker.Revoke(ctx, tokens)
		if err == nil || errors.Is(err, core.ErrRefreshTokenNotFound) || errors.Is(err, core.ErrRefreshTokenExpired) {
			return nil
		}
		return err
	}
	for _, token := range tokens {
		if err := mw.TokenStore.Delete(ctx, token); err != nil && !errors.Is(err, core.ErrRefreshTokenNotFound) && !errors.Is(err, core.ErrRefreshTokenExpired) {
			return err
		}
	}
	return nil
}

func (mw *ToukaJWTMiddleware) generateRefreshToken() (string, error) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(token), nil
}

func (mw *ToukaJWTMiddleware) newRefreshTokenState(userData any) any {
	if mw.MaxRefresh == 0 {
		return userData
	}
	return core.RefreshTokenState{
		UserData:        userData,
		MaxRefreshUntil: mw.TimeFunc().Add(mw.MaxRefresh),
	}
}

func (mw *ToukaJWTMiddleware) normalizeRefreshTokenState(userData any) any {
	switch v := userData.(type) {
	case core.RefreshTokenState:
		return v
	case *core.RefreshTokenState:
		if v == nil {
			return nil
		}
		return *v
	case map[string]any:
		state, ok := parseRefreshTokenStateMap(v)
		if ok {
			return state
		}
		return userData
	default:
		state, ok := parseRefreshTokenStateJSON(userData)
		if ok {
			return state
		}
		return userData
	}
}

func (mw *ToukaJWTMiddleware) refreshTokenUserData(userData any) any {
	switch v := userData.(type) {
	case core.RefreshTokenState:
		return v.UserData
	case *core.RefreshTokenState:
		if v == nil {
			return nil
		}
		return v.UserData
	default:
		return userData
	}
}

func (mw *ToukaJWTMiddleware) validateRefreshTokenState(userData any) error {
	switch v := userData.(type) {
	case core.RefreshTokenState:
		if !v.MaxRefreshUntil.IsZero() && !mw.TimeFunc().Before(v.MaxRefreshUntil) {
			return core.ErrRefreshTokenExpired
		}
	case *core.RefreshTokenState:
		if v != nil && !v.MaxRefreshUntil.IsZero() && !mw.TimeFunc().Before(v.MaxRefreshUntil) {
			return core.ErrRefreshTokenExpired
		}
	}
	return nil
}

func (mw *ToukaJWTMiddleware) refreshTokenExpiry(userData any) time.Time {
	expiry := mw.TimeFunc().Add(mw.RefreshTokenTimeout)
	switch v := userData.(type) {
	case core.RefreshTokenState:
		if !v.MaxRefreshUntil.IsZero() && v.MaxRefreshUntil.Before(expiry) {
			return v.MaxRefreshUntil
		}
	case *core.RefreshTokenState:
		if v != nil && !v.MaxRefreshUntil.IsZero() && v.MaxRefreshUntil.Before(expiry) {
			return v.MaxRefreshUntil
		}
	}
	return expiry
}

func parseTokenLookupSources(tokenLookup string) ([]tokenLookupSource, error) {
	methods := strings.Split(tokenLookup, ",")
	sources := make([]tokenLookupSource, 0, len(methods))
	for _, method := range methods {
		method = strings.TrimSpace(method)
		parts := strings.SplitN(method, ":", 2)
		if len(parts) != 2 {
			return nil, ErrInvalidTokenLookup
		}
		kind := strings.TrimSpace(parts[0])
		name := strings.TrimSpace(parts[1])
		if name == "" {
			return nil, ErrInvalidTokenLookup
		}
		switch kind {
		case "header", "query", "cookie", "param", "form":
		default:
			return nil, ErrInvalidTokenLookup
		}
		sources = append(sources, tokenLookupSource{kind: kind, name: name})
	}
	if len(sources) == 0 {
		return nil, ErrInvalidTokenLookup
	}
	return sources, nil
}

func (mw *ToukaJWTMiddleware) extractRefreshToken(c *touka.Context) string {
	if token, _ := c.GetCookie(mw.RefreshTokenCookieName); token != "" {
		return token
	}
	if token := c.PostForm(mw.RefreshTokenCookieName); token != "" {
		return token
	}
	return ""
}

func (mw *ToukaJWTMiddleware) refreshTokenManager() core.RefreshTokenManager {
	if mw.RefreshTokenManager != nil {
		return mw.RefreshTokenManager
	}
	return tokenStoreRefreshTokenManager{mw: mw}
}

func (m tokenStoreRefreshTokenManager) Store(ctx context.Context, token string, userData any, expiry time.Time) error {
	if m.mw.TokenStore == nil {
		return errors.New("token store is missing")
	}
	return m.mw.TokenStore.Set(ctx, token, userData, expiry)
}

func (m tokenStoreRefreshTokenManager) Lookup(ctx context.Context, token string) (any, error) {
	if m.mw.TokenStore == nil {
		return nil, errors.New("token store is missing")
	}
	return m.mw.TokenStore.Get(ctx, token)
}

func (m tokenStoreRefreshTokenManager) Rotate(ctx context.Context, oldToken, newToken string, userData any, expiry time.Time) error {
	if m.mw.TokenStore == nil {
		return errors.New("token store is missing")
	}
	unlock := acquireRefreshTokenLock(oldToken)
	defer unlock()
	currentToken, err := m.mw.TokenStore.Get(ctx, oldToken)
	if err != nil {
		return err
	}
	currentToken = m.mw.normalizeRefreshTokenState(currentToken)
	if currentToken == nil {
		return core.ErrRefreshTokenNotFound
	}
	if err := m.mw.validateRefreshTokenState(currentToken); err != nil {
		return err
	}
	expiry = m.mw.refreshTokenExpiry(currentToken)
	if rotator, ok := m.mw.TokenStore.(core.RefreshTokenRotator); ok {
		if err := rotator.Rotate(ctx, oldToken, newToken, currentToken, expiry); err != nil {
			return err
		}
		setRefreshTokenSuccessor(oldToken, newToken, expiry, m.mw.TimeFunc())
		return nil
	}
	return ErrUnsafeRefreshRotation
}

func (m tokenStoreRefreshTokenManager) Revoke(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	tokens, unlock := lockRefreshTokenChain(token, m.mw.TimeFunc())
	defer unlock()
	if err := m.mw.revokeRefreshTokenChain(ctx, tokens); err != nil {
		return err
	}
	deleteRefreshTokenSuccessors(tokens)
	return nil
}

func (mw *ToukaJWTMiddleware) signedString(token *jwt.Token) (string, error) {
	return token.SignedString(mw.Key)
}

func (mw *ToukaJWTMiddleware) ParseToken(c *touka.Context) (*jwt.Token, error) {
	var token string
	for _, source := range mw.tokenSources {
		if len(token) > 0 {
			break
		}
		switch source.kind {
		case "header":
			token = mw.jwtFromHeader(c, source.name)
		case "query":
			token = c.Query(source.name)
		case "cookie":
			token, _ = c.GetCookie(source.name)
		case "param":
			token = c.Param(source.name)
		case "form":
			token = c.PostForm(source.name)
		}
	}
	if token == "" {
		return nil, ErrEmptyAuthHeader
	}
	parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		if t.Method == nil || t.Method.Alg() != mw.algorithm.Alg() {
			return nil, ErrInvalidSigningAlgorithm
		}
		if mw.KeyFunc != nil {
			return mw.KeyFunc(t)
		}
		return mw.verifyKey, nil
	}, mw.parserOptions()...)
	if err != nil {
		return nil, err
	}
	c.Set("JWT_TOKEN", token)
	return parsedToken, nil
}

func (mw *ToukaJWTMiddleware) jwtFromHeader(c *touka.Context, key string) string {
	authHeader := c.Request.Header.Get(key)
	if authHeader == "" {
		return ""
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) != strings.TrimSpace(mw.TokenHeadName) {
		return ""
	}
	return parts[1]
}

func (mw *ToukaJWTMiddleware) handleTokenError(c *touka.Context, err error) {
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrExpiredToken, c))
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(err, c))
	default:
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(err, c))
	}
}

func (mw *ToukaJWTMiddleware) validateClaimsExpiry(claims jwt.MapClaims) error {
	rawExp := claims[mw.ExpField]
	if rawExp == nil {
		return ErrMissingExpField
	}
	exp, err := parseNumericDate(rawExp)
	if err != nil {
		return ErrWrongFormatOfExp
	}
	if !mw.TimeFunc().Before(exp) {
		return jwt.ErrTokenExpired
	}
	return nil
}

func parseNumericDate(value any) (time.Time, error) {
	switch v := value.(type) {
	case float64:
		return time.Unix(int64(v), 0), nil
	case float32:
		return time.Unix(int64(v), 0), nil
	case int64:
		return time.Unix(v, 0), nil
	case int32:
		return time.Unix(int64(v), 0), nil
	case int:
		return time.Unix(int64(v), 0), nil
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return time.Time{}, err
		}
		return time.Unix(n, 0), nil
	default:
		return time.Time{}, ErrWrongFormatOfExp
	}
}

func (mw *ToukaJWTMiddleware) parserOptions() []jwt.ParserOption {
	options := []jwt.ParserOption{jwt.WithTimeFunc(mw.TimeFunc)}
	return append(options, mw.ParseOptions...)
}

func (mw *ToukaJWTMiddleware) unauthorized(c *touka.Context, code int, message string) {
	c.SetHeader("WWW-Authenticate", "Bearer realm=\""+mw.Realm+"\"")
	if !mw.DisabledAbort {
		c.Abort()
	}
	mw.Unauthorized(c, code, message)
}

func (mw *ToukaJWTMiddleware) SetCookie(c *touka.Context, token string) {
	if mw.SendCookie {
		maxage := int(mw.Timeout.Seconds())
		if mw.CookieMaxAge > 0 {
			maxage = int(mw.CookieMaxAge.Seconds())
		}
		mw.writeCookie(c, mw.CookieName, token, maxage, mw.SecureCookie, mw.CookieHTTPOnly)
	}
}

func (mw *ToukaJWTMiddleware) setAccessTokenCookie(c *touka.Context, token string, expiresAt int64) {
	if !mw.SendCookie {
		return
	}
	maxage := int(mw.Timeout.Seconds())
	if mw.CookieMaxAge > 0 {
		maxage = int(mw.CookieMaxAge.Seconds())
	} else if expiresAt > 0 {
		remaining := expiresAt - mw.TimeFunc().Unix()
		if remaining < 0 {
			remaining = 0
		}
		maxage = int(remaining)
	}
	mw.writeCookie(c, mw.CookieName, token, maxage, mw.SecureCookie, mw.CookieHTTPOnly)
}

func (mw *ToukaJWTMiddleware) SetRefreshTokenCookie(c *touka.Context, token string, refreshExpiresAt ...int64) {
	if mw.SendCookie {
		maxage := int(mw.RefreshTokenTimeout.Seconds())
		if len(refreshExpiresAt) > 0 && refreshExpiresAt[0] > 0 {
			remaining := refreshExpiresAt[0] - mw.TimeFunc().Unix()
			if remaining < 0 {
				remaining = 0
			}
			maxage = int(remaining)
		}
		mw.writeCookie(c, mw.RefreshTokenCookieName, token, maxage, mw.RefreshTokenSecureCookie, mw.RefreshTokenCookieHTTPOnly)
	}
}

func (mw *ToukaJWTMiddleware) writeCookie(c *touka.Context, name, token string, maxage int, secure, httpOnly bool) {
	if mw.CookieSameSite != 0 {
		c.SetSameSite(mw.CookieSameSite)
	}
	c.SetCookie(name, token, maxage, "/", mw.CookieDomain, secure, httpOnly)
}

func acquireRefreshTokenLock(token string) func() {
	refreshTokenLocksMu.Lock()
	entry := refreshTokenLocks[token]
	if entry == nil {
		entry = &refreshTokenLockEntry{}
		refreshTokenLocks[token] = entry
	}
	entry.refs++
	refreshTokenLocksMu.Unlock()

	entry.mu.Lock()

	return func() {
		entry.mu.Unlock()
		refreshTokenLocksMu.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(refreshTokenLocks, token)
		}
		refreshTokenLocksMu.Unlock()
	}
}

func lockRefreshTokenChain(token string, now time.Time) ([]string, func()) {
	if token == "" {
		return nil, func() {}
	}
	seen := map[string]struct{}{}
	tokens := []string{}
	unlockers := []func(){}
	for token != "" {
		if _, ok := seen[token]; ok {
			break
		}
		seen[token] = struct{}{}
		unlockers = append(unlockers, acquireRefreshTokenLock(token))
		tokens = append(tokens, token)
		// Expired successor edges terminate logout traversal so a stale ancestor
		// token cannot keep revoking newer sessions after its own expiry window.
		token = nextRefreshToken(token, now)
	}
	return tokens, func() {
		for i := len(unlockers) - 1; i >= 0; i-- {
			unlockers[i]()
		}
	}
}

func setRefreshTokenSuccessor(oldToken, newToken string, expiry, now time.Time) {
	refreshTokenChainMu.Lock()
	refreshTokenChain[oldToken] = refreshTokenChainEntry{next: newToken, expiry: expiry}
	refreshTokenChainSweeps++
	if refreshTokenChainSweeps >= refreshTokenChainSweepAt {
		sweepExpiredRefreshTokenSuccessorsLocked(now)
		refreshTokenChainSweeps = 0
	}
	refreshTokenChainMu.Unlock()
}

func nextRefreshToken(token string, now time.Time) string {
	refreshTokenChainMu.Lock()
	entry, ok := refreshTokenChain[token]
	if ok && !entry.expiry.IsZero() && !now.Before(entry.expiry) {
		delete(refreshTokenChain, token)
		refreshTokenChainMu.Unlock()
		return ""
	}
	refreshTokenChainMu.Unlock()
	if !ok {
		return ""
	}
	return entry.next
}

func deleteRefreshTokenSuccessors(tokens []string) {
	if len(tokens) == 0 {
		return
	}
	refreshTokenChainMu.Lock()
	for _, token := range tokens {
		delete(refreshTokenChain, token)
	}
	refreshTokenChainMu.Unlock()
}

func sweepExpiredRefreshTokenSuccessorsLocked(now time.Time) {
	for token, entry := range refreshTokenChain {
		if !entry.expiry.IsZero() && !now.Before(entry.expiry) {
			delete(refreshTokenChain, token)
		}
	}
}

func parseRefreshTokenStateMap(data map[string]any) (core.RefreshTokenState, bool) {
	rawUserData, hasUserData := data["user_data"]
	if !hasUserData {
		return core.RefreshTokenState{}, false
	}
	state := core.RefreshTokenState{UserData: rawUserData}
	rawMaxRefresh, hasMaxRefresh := data["max_refresh_until"]
	if !hasMaxRefresh || rawMaxRefresh == nil {
		return state, true
	}
	switch v := rawMaxRefresh.(type) {
	case time.Time:
		state.MaxRefreshUntil = v
		return state, true
	case string:
		parsed, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			parsed, err = time.Parse(time.RFC3339, v)
			if err != nil {
				return core.RefreshTokenState{}, false
			}
		}
		state.MaxRefreshUntil = parsed
		return state, true
	default:
		return core.RefreshTokenState{}, false
	}
}

func parseRefreshTokenStateJSON(data any) (core.RefreshTokenState, bool) {
	switch v := data.(type) {
	case []byte:
		var state core.RefreshTokenState
		if err := json.Unmarshal(v, &state); err != nil {
			return core.RefreshTokenState{}, false
		}
		return state, true
	case string:
		var state core.RefreshTokenState
		if err := json.Unmarshal([]byte(v), &state); err != nil {
			return core.RefreshTokenState{}, false
		}
		return state, true
	default:
		return core.RefreshTokenState{}, false
	}
}

func ExtractClaims(c *touka.Context) jwt.MapClaims {
	claims, exists := c.Get("JWT_PAYLOAD")
	if !exists {
		return make(jwt.MapClaims)
	}
	return claims.(jwt.MapClaims)
}

func ExtractClaimsFromToken(token *jwt.Token) jwt.MapClaims {
	if token == nil {
		return make(jwt.MapClaims)
	}
	return token.Claims.(jwt.MapClaims)
}

func GetToken(c *touka.Context) string {
	token, exists := c.Get("JWT_TOKEN")
	if !exists {
		return ""
	}
	return token.(string)
}
