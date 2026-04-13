package jwt

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fenthope/jwt/core"
	"github.com/fenthope/jwt/store"
	"github.com/golang-jwt/jwt/v5"
	"github.com/infinite-iroha/touka"
)

type MapClaims jwt.MapClaims

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

	TokenStore core.TokenStore

	algorithm     Algorithm
	verifyKey     any
	inMemoryStore *store.InMemoryRefreshTokenStore
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
	// Refresh token cookie security defaults to true for enhanced security
	mw.RefreshTokenSecureCookie = true
	mw.RefreshTokenCookieHTTPOnly = true
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

	if mw.TokenStore == nil {
		mw.inMemoryStore = store.NewInMemoryRefreshTokenStore()
		mw.TokenStore = mw.inMemoryStore
	}

	if mw.Realm == "" {
		return ErrMissingRealm
	}
	if mw.SigningAlgorithm != SigningAlgorithmMLDSA65 {
		if _, ok := LookupAlgorithm(mw.SigningAlgorithm); !ok {
			return ErrInvalidSigningAlgorithm
		}
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
	if claims[mw.ExpField] == nil {
		mw.unauthorized(c, http.StatusBadRequest, mw.HTTPStatusMessageFunc(ErrMissingExpField, c))
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
	mw.SetCookie(c, tokenPair.AccessToken)
	mw.SetRefreshTokenCookie(c, tokenPair.RefreshToken)
	mw.LoginResponse(c, http.StatusOK, tokenPair)
}

func (mw *ToukaJWTMiddleware) LogoutHandler(c *touka.Context) {
	if mw.SendCookie {
		c.SetCookie(mw.CookieName, "", -1, "/", mw.CookieDomain, mw.SecureCookie, mw.CookieHTTPOnly)
		c.SetCookie(mw.RefreshTokenCookieName, "", -1, "/", mw.CookieDomain, mw.RefreshTokenSecureCookie, mw.RefreshTokenCookieHTTPOnly)
	}
	mw.LogoutResponse(c, http.StatusOK)
}

func (mw *ToukaJWTMiddleware) RefreshHandler(c *touka.Context) {
	refreshToken := mw.extractRefreshToken(c)
	if refreshToken == "" {
		mw.unauthorized(c, http.StatusBadRequest, mw.HTTPStatusMessageFunc(ErrMissingRefreshToken, c))
		return
	}
	userData, err := mw.TokenStore.Get(c.Request.Context(), refreshToken)
	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(err, c))
		return
	}
	tokenPair, err := mw.generateTokenPair(userData)
	if err != nil {
		mw.unauthorized(c, http.StatusInternalServerError, mw.HTTPStatusMessageFunc(err, c))
		return
	}
	if err := mw.rotateRefreshToken(c.Request.Context(), refreshToken, tokenPair.RefreshToken, userData); err != nil {
		mw.unauthorized(c, http.StatusInternalServerError, mw.HTTPStatusMessageFunc(err, c))
		return
	}
	mw.SetCookie(c, tokenPair.AccessToken)
	mw.SetRefreshTokenCookie(c, tokenPair.RefreshToken)
	mw.RefreshResponse(c, http.StatusOK, tokenPair)
}

func (mw *ToukaJWTMiddleware) TokenGenerator(ctx context.Context, data any) (*core.Token, error) {
	tokenPair, err := mw.generateTokenPair(data)
	if err != nil {
		return nil, err
	}
	err = mw.TokenStore.Set(ctx, tokenPair.RefreshToken, data, mw.TimeFunc().Add(mw.RefreshTokenTimeout))
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
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expire.Unix(),
		CreatedAt:    mw.TimeFunc().Unix(),
		TokenType:    "Bearer",
	}, nil
}

func (mw *ToukaJWTMiddleware) rotateRefreshToken(ctx context.Context, oldToken, newToken string, userData any) error {
	expiry := mw.TimeFunc().Add(mw.RefreshTokenTimeout)
	if rotator, ok := mw.TokenStore.(core.RefreshTokenRotator); ok {
		return rotator.Rotate(ctx, oldToken, newToken, userData, expiry)
	}
	if err := mw.TokenStore.Set(ctx, newToken, userData, expiry); err != nil {
		return err
	}
	if err := mw.TokenStore.Delete(ctx, oldToken); err != nil {
		if rmErr := mw.TokenStore.Delete(ctx, newToken); rmErr != nil {
			log.Printf("WARN: refresh token rotation rollback failed: failed to delete old token: %v, failed to delete new token: %v, new token may be orphaned", err, rmErr)
		}
		return err
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

func (mw *ToukaJWTMiddleware) extractRefreshToken(c *touka.Context) string {
	if token, _ := c.GetCookie(mw.RefreshTokenCookieName); token != "" {
		return token
	}
	if token := c.PostForm(mw.RefreshTokenCookieName); token != "" {
		return token
	}
	return ""
}

func (mw *ToukaJWTMiddleware) signedString(token *jwt.Token) (string, error) {
	return token.SignedString(mw.Key)
}

func (mw *ToukaJWTMiddleware) ParseToken(c *touka.Context) (*jwt.Token, error) {
	var token string
	methods := strings.Split(mw.TokenLookup, ",")
	for _, method := range methods {
		if len(token) > 0 {
			break
		}
		parts := strings.Split(strings.TrimSpace(method), ":")
		k, v := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		switch k {
		case "header":
			token = mw.jwtFromHeader(c, v)
		case "query":
			token = c.Query(v)
		case "cookie":
			token, _ = c.GetCookie(v)
		case "param":
			token = c.Param(v)
		case "form":
			token = c.PostForm(v)
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
	}, mw.ParseOptions...)
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
	default:
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(err, c))
	}
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
		c.SetCookie(mw.CookieName, token, maxage, "/", mw.CookieDomain, mw.SecureCookie, mw.CookieHTTPOnly)
	}
}

func (mw *ToukaJWTMiddleware) SetRefreshTokenCookie(c *touka.Context, token string) {
	if mw.SendCookie {
		maxage := int(mw.RefreshTokenTimeout.Seconds())
		c.SetCookie(mw.RefreshTokenCookieName, token, maxage, "/", mw.CookieDomain, mw.RefreshTokenSecureCookie, mw.RefreshTokenCookieHTTPOnly)
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
