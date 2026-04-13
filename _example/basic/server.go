package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"filippo.io/mldsa"
	"github.com/fenthope/jwt"
	"github.com/fenthope/jwt/core"
	"github.com/infinite-iroha/touka"
)

type login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

var (
	identityKey = "id"
	port        string
)

type User struct {
	UserName  string
	FirstName string
	LastName  string
}

func init() {
	port = os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}
}

func main() {
	engine := touka.Default()
	authMiddleware, err := jwt.New(initParams())
	if err != nil {
		log.Fatal("JWT Error:" + err.Error())
	}

	registerRoute(engine, authMiddleware)

	if err = http.ListenAndServe(":"+port, engine); err != nil {
		log.Fatal(err)
	}
}

func registerRoute(r *touka.Engine, handle *jwt.ToukaJWTMiddleware) {
	r.POST("/login", handle.LoginHandler)
	r.POST("/refresh_token", handle.RefreshHandler)

	auth := r.Group("/auth", handle.MiddlewareFunc())
	auth.GET("/hello", helloHandler)
}

func initParams() *jwt.ToukaJWTMiddleware {
	privateKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		log.Fatal(err)
	}
	return &jwt.ToukaJWTMiddleware{
		Realm:       "test zone",
		Key:         privateKey,
		Timeout:     time.Hour,
		MaxRefresh:  time.Hour * 24 * 7,
		IdentityKey: identityKey,
		PayloadFunc: payloadFunc(),

		IdentityHandler: identityHandler(),
		Authenticator:   authenticator(),
		Authorizator:    authorizator(),
		Unauthorized:    unauthorized(),
		TokenLookup:     "header: Authorization, query: token, cookie: jwt",
		TokenHeadName:   "Bearer",
		TimeFunc:        time.Now,
	}
}

func payloadFunc() func(data any) jwt.MapClaims {
	return func(data any) jwt.MapClaims {
		if v, ok := data.(*User); ok {
			return jwt.MapClaims{
				identityKey: v.UserName,
			}
		}
		return jwt.MapClaims{}
	}
}

func identityHandler() func(c *touka.Context) any {
	return func(c *touka.Context) any {
		claims := jwt.ExtractClaims(c)
		return &User{
			UserName: claims[identityKey].(string),
		}
	}
}

func authenticator() func(c *touka.Context) (any, error) {
	return func(c *touka.Context) (any, error) {
		var loginVals login
		if err := c.ShouldBind(&loginVals); err != nil {
			return "", jwt.ErrMissingLoginValues
		}
		userID := loginVals.Username
		password := loginVals.Password

		if (userID == "admin" && password == "admin") || (userID == "test" && password == "test") {
			return &User{
				UserName:  userID,
				LastName:  "Bo-Yi",
				FirstName: "Wu",
			}, nil
		}
		return nil, jwt.ErrFailedAuthentication
	}
}

func authorizator() func(data any, c *touka.Context) bool {
	return func(data any, c *touka.Context) bool {
		if v, ok := data.(*User); ok && v.UserName == "admin" {
			return true
		}
		return false
	}
}

func unauthorized() func(c *touka.Context, code int, message string) {
	return func(c *touka.Context, code int, message string) {
		c.JSON(code, touka.H{
			"code":    code,
			"message": message,
		})
	}
}

func helloHandler(c *touka.Context) {
	claims := jwt.ExtractClaims(c)
	user, _ := c.Get(identityKey)
	c.JSON(200, touka.H{
		"userID":   claims[identityKey],
		"userName": user.(*User).UserName,
		"text":     "Hello World.",
	})
}
