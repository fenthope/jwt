package jwt

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/appleboy/gofight/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/infinite-iroha/touka"
	"github.com/stretchr/testify/assert"
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

func makeTokenString(username string) string {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["identity"] = username
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	claims["orig_iat"] = time.Now().Unix()
	s, _ := token.SignedString(key)
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
