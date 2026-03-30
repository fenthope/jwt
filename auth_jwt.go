package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fenthope/jwt/core"
	"github.com/fenthope/jwt/store"
	"github.com/golang-jwt/jwt/v5"
	"github.com/infinite-iroha/touka"
	"github.com/youmark/pkcs8"
)

type MapClaims jwt.MapClaims

type ToukaJWTMiddleware struct {
	Realm            string
	SigningAlgorithm string
	Key              []byte
	KeyFunc          func(token *jwt.Token) (any, error)
	Timeout          time.Duration
	TimeoutFunc      func(data any) time.Duration

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
	RefreshTokenCookieSameSite http.SameSite

	PayloadFunc       func(data any) MapClaims
	IdentityHandler   func(c *touka.Context) any
	ParseOptions      []jwt.ParserOption
	SendAuthorization bool

	PrivKeyFile          string
	PrivKeyBytes         []byte
	PubKeyFile           string
	PubKeyBytes          []byte
	PrivateKeyPassphrase string

	TokenStore core.TokenStore

	privKey       *rsa.PrivateKey
	pubKey        *rsa.PublicKey
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
	ErrNoPrivKeyFile            = errors.New("private key file is missing")
	ErrNoPubKeyFile             = errors.New("public key file is missing")
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
	ErrExpiredToken             = errors.New("token is expired")
	ErrTokenNotValidYet         = errors.New("token is not valid yet")
	ErrMissingRefreshToken      = errors.New("refresh token is missing")
)

type refreshTokenConsumer interface {
	Consume(ctx context.Context, token string) (any, error)
}

type refreshTokenRotator interface {
	Rotate(ctx context.Context, oldToken, newToken string, userData any, expiry time.Time) error
}

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
		mw.SigningAlgorithm = "HS256"
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
	if !mw.RefreshTokenSecureCookie {
		mw.RefreshTokenSecureCookie = mw.SecureCookie
	}
	if !mw.RefreshTokenCookieHTTPOnly {
		mw.RefreshTokenCookieHTTPOnly = mw.CookieHTTPOnly
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

	if mw.TokenStore == nil {
		mw.inMemoryStore = store.NewInMemoryRefreshTokenStore()
		mw.TokenStore = mw.inMemoryStore
	}

	if mw.Realm == "" {
		return ErrMissingRealm
	}
	if mw.usingPublicKeyAlgo() {
		return mw.readKeys()
	}
	if mw.Key == nil {
		return ErrMissingSecretKey
	}
	return nil
}

func (mw *ToukaJWTMiddleware) readKeys() error {
	if err := mw.privateKey(); err != nil {
		return err
	}
	return mw.publicKey()
}

func (mw *ToukaJWTMiddleware) privateKey() error {
	var keyData []byte
	if mw.PrivKeyFile == "" {
		if len(mw.PrivKeyBytes) > 0 {
			keyData = mw.PrivKeyBytes
		} else {
			return ErrNoPrivKeyFile
		}
	} else {
		filecontent, err := os.ReadFile(mw.PrivKeyFile)
		if err != nil {
			return ErrNoPrivKeyFile
		}
		keyData = filecontent
	}
	if mw.PrivateKeyPassphrase != "" {
		key, err := pkcs8.ParsePKCS8PrivateKey(keyData, []byte(mw.PrivateKeyPassphrase))
		if err != nil {
			return ErrInvalidPrivKey
		}
		var ok bool
		mw.privKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return ErrInvalidPrivKey
		}
	} else {
		key, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
		if err != nil {
			return ErrInvalidPrivKey
		}
		mw.privKey = key
	}
	return nil
}

func (mw *ToukaJWTMiddleware) publicKey() error {
	var keyData []byte
	if mw.PubKeyFile == "" {
		if len(mw.PubKeyBytes) > 0 {
			keyData = mw.PubKeyBytes
		} else {
			return ErrNoPubKeyFile
		}
	} else {
		filecontent, err := os.ReadFile(mw.PubKeyFile)
		if err != nil {
			return ErrNoPubKeyFile
		}
		keyData = filecontent
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		return ErrInvalidPubKey
	}
	mw.pubKey = key
	return nil
}

func (mw *ToukaJWTMiddleware) usingPublicKeyAlgo() bool {
	switch mw.SigningAlgorithm {
	case "RS256", "RS384", "RS512":
		return true
	}
	return false
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
		c.SetCookie(mw.RefreshTokenCookieName, "", -1, "/", mw.CookieDomain, mw.SecureCookie, mw.CookieHTTPOnly)
	}
	mw.LogoutResponse(c, http.StatusOK)
}

func (mw *ToukaJWTMiddleware) RefreshHandler(c *touka.Context) {
	refreshToken := mw.extractRefreshToken(c)
	if refreshToken == "" {
		mw.unauthorized(c, http.StatusBadRequest, mw.HTTPStatusMessageFunc(ErrMissingRefreshToken, c))
		return
	}
	ctx := c.Request.Context()
	var (
		userData any
		err      error
	)
	userData, err = mw.TokenStore.Get(ctx, refreshToken)
	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(err, c))
		return
	}
	tokenPair, err := mw.generateTokenPair(ctx, userData, false)
	if err != nil {
		mw.unauthorized(c, http.StatusInternalServerError, mw.HTTPStatusMessageFunc(err, c))
		return
	}
	if rotator, ok := mw.TokenStore.(refreshTokenRotator); ok {
		err = rotator.Rotate(ctx, refreshToken, tokenPair.RefreshToken, userData, time.Unix(tokenPair.CreatedAt, 0).Add(mw.RefreshTokenTimeout))
	} else {
		err = mw.TokenStore.Set(ctx, tokenPair.RefreshToken, userData, time.Unix(tokenPair.CreatedAt, 0).Add(mw.RefreshTokenTimeout))
		if err == nil {
			err = mw.TokenStore.Delete(ctx, refreshToken)
			if err != nil {
				_ = mw.TokenStore.Delete(ctx, tokenPair.RefreshToken)
			}
		}
	}
	if err != nil {
		mw.unauthorized(c, http.StatusInternalServerError, mw.HTTPStatusMessageFunc(err, c))
		return
	}
	mw.SetCookie(c, tokenPair.AccessToken)
	mw.SetRefreshTokenCookie(c, tokenPair.RefreshToken)
	mw.RefreshResponse(c, http.StatusOK, tokenPair)
}

func (mw *ToukaJWTMiddleware) TokenGenerator(ctx context.Context, data any) (*core.Token, error) {
	return mw.generateTokenPair(ctx, data, true)
}

func (mw *ToukaJWTMiddleware) generateTokenPair(ctx context.Context, data any, persistRefreshToken bool) (*core.Token, error) {
	token := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))
	token.Header["typ"] = "JWT"
	claims := token.Claims.(jwt.MapClaims)
	if mw.PayloadFunc != nil {
		for k, v := range mw.PayloadFunc(data) {
			claims[k] = v
		}
	}
	now := mw.TimeFunc()
	expire := now.Add(mw.TimeoutFunc(data))
	claims[mw.ExpField] = expire.Unix()
	claims["iat"] = now.Unix()
	claims["orig_iat"] = now.Unix()
	accessToken, err := mw.signedString(token)
	if err != nil {
		return nil, err
	}

	refreshToken, err := mw.generateRefreshToken()
	if err != nil {
		return nil, err
	}

	refreshExpiry := now.Add(mw.RefreshTokenTimeout)
	if persistRefreshToken {
		err = mw.TokenStore.Set(ctx, refreshToken, data, refreshExpiry)
		if err != nil {
			return nil, err
		}
	}

	return &core.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expire.Unix(),
		CreatedAt:    now.Unix(),
		TokenType:    "Bearer",
	}, nil
}

func (mw *ToukaJWTMiddleware) generateRefreshToken() (string, error) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(token), nil
}

func (mw *ToukaJWTMiddleware) extractRefreshToken(c *touka.Context) string {
	if token, _ := c.GetCookie(mw.RefreshTokenCookieName); token != "" {
		return token
	}
	if token := c.PostForm(mw.RefreshTokenCookieName); token != "" {
		return token
	}
	if token := c.Query(mw.RefreshTokenCookieName); token != "" {
		return token
	}
	return ""
}

func (mw *ToukaJWTMiddleware) signedString(token *jwt.Token) (string, error) {
	if mw.usingPublicKeyAlgo() {
		return token.SignedString(mw.privKey)
	}
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
		if len(parts) != 2 {
			continue
		}
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
	parseOptions := mw.buildParseOptions()
	parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		if jwt.GetSigningMethod(mw.SigningAlgorithm) != t.Method {
			return nil, ErrInvalidSigningAlgorithm
		}
		if mw.KeyFunc != nil {
			return mw.KeyFunc(t)
		}
		c.Set("JWT_TOKEN", token)
		if mw.usingPublicKeyAlgo() {
			return mw.pubKey, nil
		}
		return mw.Key, nil
	}, parseOptions...)
	if err != nil {
		return nil, err
	}
	if !parsedToken.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return parsedToken, nil
}

func (mw *ToukaJWTMiddleware) buildParseOptions() []jwt.ParserOption {
	baseOptions := []jwt.ParserOption{
		jwt.WithValidMethods([]string{mw.SigningAlgorithm}),
		jwt.WithTimeFunc(mw.TimeFunc),
	}
	if mw.ExpField == "exp" {
		baseOptions = append(baseOptions, jwt.WithExpirationRequired())
	}
	return append(baseOptions, mw.ParseOptions...)
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
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrTokenNotValidYet, c))
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
		if mw.CookieMaxAge > 0 {
			maxage = int(mw.CookieMaxAge.Seconds())
		}
		c.SetCookie(mw.CookieName, token, maxage, "/", mw.CookieDomain, mw.SecureCookie, mw.CookieHTTPOnly, mw.CookieSameSite)
	}
}

func (mw *ToukaJWTMiddleware) SetRefreshTokenCookie(c *touka.Context, token string) {
	if mw.SendCookie {
		maxage := int(mw.RefreshTokenTimeout.Seconds())
		c.SetCookie(mw.RefreshTokenCookieName, token, maxage, "/", mw.CookieDomain, mw.RefreshTokenSecureCookie, mw.RefreshTokenCookieHTTPOnly, mw.RefreshTokenCookieSameSite)
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
