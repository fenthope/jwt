# 示例

本文档提供 Touka JWT Middleware 的常见使用示例。

## 1. Basic Usage

最基础的使用方式，适合快速集成。

```go
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"filippo.io/mldsa"
	"github.com/fenthope/jwt"
	"github.com/infinite-iroha/touka"
)

type login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

type User struct {
	UserName  string
	FirstName string
	LastName  string
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

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
		IdentityKey: "id",
		PayloadFunc: payloadFunc(),
		IdentityHandler: identityHandler(),
		Authenticator: authenticator(),
		Authorizator: authorizator(),
		Unauthorized: unauthorized(),
		TokenLookup:  "header: Authorization, query: token, cookie: jwt",
		TokenHeadName: "Bearer",
		TimeFunc: time.Now,
	}
}

func payloadFunc() func(data any) jwt.MapClaims {
	return func(data any) jwt.MapClaims {
		if v, ok := data.(*User); ok {
			return jwt.MapClaims{"id": v.UserName}
		}
		return jwt.MapClaims{}
	}
}

func identityHandler() func(c *touka.Context) any {
	return func(c *touka.Context) any {
		claims := jwt.ExtractClaims(c)
		return &User{
			UserName: claims["id"].(string),
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
				UserName: userID,
				LastName: "Bo-Yi",
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
	user, _ := c.Get("id")
	c.JSON(200, touka.H{
		"userID":   claims["id"],
		"userName": user.(*User).UserName,
		"text":     "Hello World.",
	})
}
```

**请求示例：**

```sh
# 登录
curl -X POST http://localhost:8000/login \
-d "username=admin&password=admin"

# 访问受保护接口（需要 access_token）
curl http://localhost:8000/auth/hello \
-H "Authorization: Bearer <access_token>"
```

## 2. Verify-Only Mode

如果服务只负责验证 token、不负责签发，可以使用 Verify-Only 模式。此时只需提供公钥，无法调用 `LoginHandler` 和 `RefreshHandler`。

```go
package main

import (
    "log"
    "net/http"
    "time"

    "filippo.io/mldsa"
    jwtmw "github.com/fenthope/jwt"
    "github.com/infinite-iroha/touka"
)

func main() {
    // 生成密钥对（生产环境应持久化）
    privateKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
    if err != nil {
        log.Fatal(err)
    }

    // 只提供公钥，不提供私钥
    authMiddleware, err := jwtmw.New(&jwtmw.ToukaJWTMiddleware{
        Realm:      "api",
        Key:        privateKey, // 签发时需要私钥，验证时实际使用公钥
        PubKeyBytes: privateKey.PublicKey().Bytes(), // 显式指定公钥
        Timeout:    time.Hour,
        IdentityKey: "user_id",

        // Verify-Only 模式下 Authenticator 不会被调用
        // 但字段仍需存在以通过初始化检查
        Authenticator: func(c *touka.Context) (any, error) {
            return nil, nil
        },
    })
    if err != nil {
        log.Fatal(err)
    }

    engine := touka.Default()

    // 只能使用中间件验证 token，不能登录或刷新
    protected := engine.Group("/api", authMiddleware.MiddlewareFunc())
    protected.GET("/data", dataHandler)

    log.Fatal(http.ListenAndServe(":8080", engine))
}

func dataHandler(c *touka.Context) {
    claims := jwtmw.ExtractClaims(c)
    c.JSON(200, touka.H{
        "user_id": claims["user_id"],
        "message": "verified",
    })
}
```

**适用场景：**
- API 网关
- 资源服务器
- 只做权限验证的微服务

## 3. Custom Authenticator

通过自定义认证逻辑，可以接入任意用户系统（数据库、LDAP、OAuth 等）。

```go
package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"log"
	"net/http"
	"time"

	"filippo.io/mldsa"
	jwtmw "github.com/fenthope/jwt"
	"github.com/infinite-iroha/touka"
	_ "github.com/mattn/go-sqlite3"
)

type User struct {
    ID       int64
    Username string
    Password string
    Role     string
}

type loginRequest struct {
    Username string `form:"username" binding:"required"`
    Password string `form:"password" binding:"required"`
}

func main() {
    privateKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
    if err != nil {
        log.Fatal(err)
    }

    db, err := sql.Open("sqlite3", ":memory:")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

// 密码哈希函数（生产环境应使用 bcrypt 或 argon2）
	hashPassword := func(password string) string {
		hash := sha256.Sum256([]byte(password + "salt")) // 简单演示，实际用 bcrypt
		return hex.EncodeToString(hash[:])
	}

	// 初始化数据库
	_, err = db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)`)
	if err != nil {
		log.Fatal(err)
	}
	// 插入用户，密码已哈希
	_, err = db.Exec(`INSERT INTO users (username, password, role) VALUES (?, ?, ?)`, "admin", hashPassword("secret"), "admin")
	if err != nil {
		log.Fatal(err)
	}

    authMiddleware, err := jwtmw.New(&jwtmw.ToukaJWTMiddleware{
        Realm:       "api",
        Key:         privateKey,
        IdentityKey: "user_id",
        Timeout:     time.Hour,
        MaxRefresh:  7 * 24 * time.Hour,

        // 自定义认证：从数据库验证用户
        Authenticator: func(c *touka.Context) (any, error) {
            var req loginRequest
            if err := c.ShouldBind(&req); err != nil {
                return nil, jwtmw.ErrMissingLoginValues
            }

var user User
	// 查询用户并验证密码哈希
	err := db.QueryRow(
		"SELECT id, username, password, role FROM users WHERE username = ?",
		req.Username,
	).Scan(&user.ID, &user.Username, &user.Password, &user.Role)

	if err == sql.ErrNoRows {
		return nil, jwtmw.ErrFailedAuthentication
	}

	// 验证密码：比对哈希值
	hashedInput := hashPassword(req.Password)
	if user.Password != hashedInput {
		return nil, jwtmw.ErrFailedAuthentication
	}
            if err != nil {
                return nil, err
            }

            // 返回完整的 User 结构体，供后续处理器使用
            return &user, nil
        },

        // 自定义 Payload：包含用户 ID 和角色
        PayloadFunc: func(data any) jwtmw.MapClaims {
            if user, ok := data.(*User); ok {
                return jwtmw.MapClaims{
                    "user_id": user.ID,
                    "role":    user.Role,
                }
            }
            return jwtmw.MapClaims{}
        },

        // 自定义身份处理：从 claims 中提取并设置到上下文
        IdentityHandler: func(c *touka.Context) any {
            claims := jwtmw.ExtractClaims(c)
            return &User{
                ID:   claims["user_id"].(int64),
                Role: claims["role"].(string),
            }
        },

        // 自定义权限校验：检查用户角色
        Authorizator: func(data any, c *touka.Context) bool {
            if user, ok := data.(*User); ok {
                return user.Role == "admin"
            }
            return false
        },
    })
    if err != nil {
        log.Fatal(err)
    }

    engine := touka.Default()
    engine.POST("/login", authMiddleware.LoginHandler)

    auth := engine.Group("/admin", authMiddleware.MiddlewareFunc())
    auth.GET("/dashboard", adminDashboardHandler)

    log.Fatal(http.ListenAndServe(":8080", engine))
}

func adminDashboardHandler(c *touka.Context) {
    user, _ := c.Get("user_id")
    c.JSON(200, touka.H{"message": "admin dashboard", "user": user})
}
```

## 4. Cookie Configuration

配置 access token 和 refresh token 的 cookie 行为。

```go
package main

import (
    "log"
    "net/http"
    "time"

    "filippo.io/mldsa"
    jwtmw "github.com/fenthope/jwt"
    "github.com/infinite-iroha/touka"
)

func main() {
    privateKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
    if err != nil {
        log.Fatal(err)
    }

    authMiddleware, err := jwtmw.New(&jwtmw.ToukaJWTMiddleware{
        Realm:       "api",
        Key:         privateKey,
        IdentityKey: "user_id",
        Timeout:     time.Hour,
        MaxRefresh:  7 * 24 * time.Hour,

        // 启用 cookie 模式
        SendCookie: true,

// Access Token Cookie 配置
	CookieName: "access_token",
	CookieDomain: "example.com",
        SecureCookie:   true,              // HTTPS 下才传输
        CookieHTTPOnly: true,              // 禁止 JavaScript 访问
        CookieSameSite: http.SameSiteStrictMode,

        // Refresh Token Cookie 配置（更长的有效期）
        RefreshTokenCookieName:     "refresh_token",
        RefreshTokenSecureCookie:   true,
        RefreshTokenCookieHTTPOnly: true,

        Authenticator: func(c *touka.Context) (any, error) {
            return "user_123", nil
        },
        PayloadFunc: func(data any) jwtmw.MapClaims {
            return jwtmw.MapClaims{"user_id": data}
        },
    })
    if err != nil {
        log.Fatal(err)
    }

    engine := touka.Default()
    engine.POST("/login", authMiddleware.LoginHandler)
    engine.POST("/refresh_token", authMiddleware.RefreshHandler)
    engine.POST("/logout", authMiddleware.LogoutHandler)

    auth := engine.Group("/api", authMiddleware.MiddlewareFunc())
    auth.GET("/profile", profileHandler)

    log.Fatal(http.ListenAndServe(":8080", engine))
}

func profileHandler(c *touka.Context) {
    userID, _ := c.Get("user_id")
    c.JSON(200, touka.H{"user_id": userID})
}
```

**Cookie 配置说明：**

| 字段 | 说明 |
|------|------|
| `SendCookie` | 是否启用 cookie 模式 |
| `CookieName` | access token cookie 名称 |
| `CookieDomain` | cookie 所属域名 |
| `SecureCookie` | 是否仅 HTTPS 传输 |
| `CookieHTTPOnly` | 是否禁止 JS 访问 |
| `CookieSameSite` | SameSite 策略 |
| `RefreshTokenCookieName` | refresh token cookie 名称 |
| `RefreshTokenSecureCookie` | refresh token 的安全设置 |
| `RefreshTokenCookieHTTPOnly` | refresh token 的 HTTP Only 设置 |

> 注意：cookie 有效期由 `Timeout`（access token）和 `RefreshTokenTimeout`（refresh token）计算，代码中不使用 `CookieMaxAge` 字段。

## 5. Token Lookup

配置 access token 的提取位置，支持多种方式组合使用。

```go
package main

import (
    "log"
    "net/http"
    "time"

    "filippo.io/mldsa"
    jwtmw "github.com/fenthope/jwt"
    "github.com/infinite-iroha/touka"
)

func main() {
    privateKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
    if err != nil {
        log.Fatal(err)
    }

    authMiddleware, err := jwtmw.New(&jwtmw.ToukaJWTMiddleware{
        Realm:       "api",
        Key:         privateKey,
        IdentityKey: "user_id",
        Timeout:     time.Hour,

        // Token 提取位置配置
        // 格式：<source>:<key>, <source>:<key>, ...
        // source 可选：header, query, cookie, param, form
        // 优先级按配置顺序
        TokenLookup:    "header:Authorization, query:token, cookie:jwt",
        TokenHeadName:  "Bearer",

        Authenticator: func(c *touka.Context) (any, error) {
            return "user_123", nil
        },
        PayloadFunc: func(data any) jwtmw.MapClaims {
            return jwtmw.MapClaims{"user_id": data}
        },
    })
    if err != nil {
        log.Fatal(err)
    }

    engine := touka.Default()
    engine.POST("/login", authMiddleware.LoginHandler)

    auth := engine.Group("/api", authMiddleware.MiddlewareFunc())
    auth.GET("/profile", profileHandler)

    log.Fatal(http.ListenAndServe(":8080", engine))
}

func profileHandler(c *touka.Context) {
    userID, _ := c.Get("user_id")
    c.JSON(200, touka.H{"user_id": userID})
}
```

**TokenLookup 配置格式：**

```
TokenLookup = "<source>:<key>, <source>:<key>, ..."
```

| source | 说明 | 示例 |
|--------|------|------|
| `header` | 请求头 | `header:X-Token` |
| `query` | URL 查询参数 | `query:token` |
| `cookie` | Cookie | `cookie:jwt` |
| `param` | 路径参数 | `param:token` |
| `form` | POST 表单 | `form:token` |

**常用配置方案：**

```go
// 仅从请求头获取（默认）
TokenLookup: "header:Authorization"

// 从请求头或 Query String 获取
TokenLookup: "header:Authorization, query:token"

// 从请求头、Query String 或 Cookie 获取
TokenLookup: "header:Authorization, query:token, cookie:jwt"

// 从多位置获取，优先级：header > cookie > query
TokenLookup: "header:Authorization, cookie:jwt, query:token"
```

**Header 格式：**

当 source 为 `header` 时，默认使用 `Bearer` 前缀。请求示例：

```sh
# 使用 Bearer token
curl http://localhost:8080/api/profile \
  -H "Authorization: Bearer eyJhbGciOiJ..."

# 使用自定义 header
TokenLookup: "header:X-Access-Token"
curl http://localhost:8080/api/profile \
  -H "X-Access-Token: eyJhbGciOiJ..."
```