# Touka JWT Middleware API 文档

## 概述

Touka JWT Middleware 提供完整的 JWT 认证解决方案，包含 token 签发、刷新、撤销和验证功能。

### 核心类型

```go
type ToukaJWTMiddleware struct {
    Realm string
    SigningAlgorithm string
    Key any
    KeyFunc func(token *jwt.Token) (any, error)
    Timeout time.Duration
    TimeoutFunc func(data any) time.Duration
    MaxRefresh time.Duration
    RefreshTokenTimeout time.Duration

    // 用户认证回调，返回的用户数据会作为 PayloadFunc 的输入和 refresh token 的关联数据
    Authenticator func(c *touka.Context) (any, error)

    // 授权回调，返回 true 表示允许访问
    Authorizator func(data any, c *touka.Context) bool

    // 响应回调，可自定义登录/登出/刷新/未授权时的响应格式
    LoginResponse  func(c *touka.Context, code int, token *core.Token)
    LogoutResponse func(c *touka.Context, code int)
    RefreshResponse func(c *touka.Context, code int, token *core.Token)
    Unauthorized   func(c *touka.Context, code int, message string)
    HTTPStatusMessageFunc func(e error, c *touka.Context) string

    // 自定义 claims 提取逻辑
    IdentityKey    string
    IdentityHandler func(c *touka.Context) any

    // 从用户数据生成 JWT claims
    PayloadFunc func(data any) MapClaims

    // token 提取配置，格式为 "source:name"，多个来源用逗号分隔
    // source 可选: header, query, cookie, param, form
    TokenLookup string
    TokenHeadName string

// cookie 配置
	SendCookie bool
	CookieName string
	CookieMaxAge time.Duration
	CookieDomain string
	SecureCookie bool
	CookieHTTPOnly bool
	CookieSameSite http.SameSite

	RefreshTokenCookieName string
	RefreshTokenSecureCookie bool
	RefreshTokenCookieHTTPOnly bool

// JWT 解析选项
	ParseOptions []jwt.ParserOption
	// 自定义时间函数，用于 token 过期时间计算
	TimeFunc func() time.Time
	// 禁用 abort
	DisabledAbort bool
	// 自定义 exp 字段名
	ExpField string
	// 是否在响应头中回传 Authorization 头
	SendAuthorization bool

    // 密钥文件配置
    PrivKeyFile string
    PrivKeyBytes []byte
    PubKeyFile string
    PubKeyBytes []byte

    // token 存储，用于 refresh token 管理和撤销
    TokenStore core.TokenStore
}
```

### Token 结构

```go
type Token struct {
	AccessToken string `json:"access_token"`
	TokenType string `json:"token_type"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresAt int64 `json:"expires_at"` // Unix 时间戳（秒）
	CreatedAt int64 `json:"created_at"`
	RefreshExpiresAt int64 `json:"refresh_expires_at,omitempty"` // refresh token 过期时间
}

// ExpiresIn() 方法返回剩余有效期（秒）
func (t *Token) ExpiresIn() int64 {
	return t.ExpiresAt - time.Now().Unix()
}
```

> 注意：实际响应中 `expire` 字段为 RFC3339 格式字符串，例如：
> ```json
> {"code": 200, "access_token": "...", "refresh_token": "...", "expire": "2024-01-01T12:00:00Z"}
> ```

### RefreshTokenManager / TokenStore / RefreshTokenRotator

```go
type RefreshTokenManager interface {
    Store(ctx context.Context, token string, userData any, expiry time.Time) error
    Lookup(ctx context.Context, token string) (any, error)
    Rotate(ctx context.Context, oldToken, newToken string, userData any, expiry time.Time) error
    Revoke(ctx context.Context, token string) error
}

type TokenStore interface {
    Set(ctx context.Context, token string, userData any, expiry time.Time) error
    Get(ctx context.Context, token string) (any, error)
    Delete(ctx context.Context, token string) error
    Cleanup(ctx context.Context) (int, error)
    Count(ctx context.Context) (int, error)
}

type RefreshTokenRotator interface {
	TokenStore
	Rotate(ctx context.Context, oldToken, newToken string, userData any, expiry time.Time) error
}

type RefreshTokenRevoker interface {
	TokenStore
	Revoke(ctx context.Context, tokens []string) error
}
```

`RefreshTokenManager` 是高层 refresh 生命周期抽象。实现它后，可以自行管理 refresh token 的持久化、查找、原子轮换和注销逻辑；middleware 不再要求你复用进程内 successor 链或 `TokenStore` 的低层组合语义。

实现 `RefreshTokenRevoker` 的 store 可以让兼容模式下的 `LogoutHandler` 原子性地撤销整条 refresh token 链。

`RefreshTokenManager` 优先级高于 `TokenStore`。默认情况下未显式配置 manager 时，middleware 会创建内存 store：`store.NewInMemoryRefreshTokenStoreWithClock(mw.TimeFunc)`，并通过兼容适配层把它当作 refresh manager 使用。

`TokenStore` 用于兼容模式下持久化 refresh token 及其关联的 `userData`。

`RefreshTokenRotator` 用于兼容模式下原子地将旧 refresh token 轮换为新 token。`RefreshHandler` 在未配置 `RefreshTokenManager` 时要求 `TokenStore` 实现该接口，否则返回 `ErrUnsafeRefreshRotation`。

当配置了 `MaxRefresh` 时，store 中保存的数据不是裸 `userData`，而是：

```go
type RefreshTokenState struct {
    UserData any       `json:"user_data"`
    MaxRefreshUntil time.Time `json:"max_refresh_until,omitempty"`
}
```

---

## LoginHandler

用户登录，验证凭据后签发 access token 和 refresh token。

### 函数签名

```go
func (mw *ToukaJWTMiddleware) LoginHandler(c *touka.Context)
```

### 参数

| 参数 | 类型 | 说明 |
|------|------|------|
| c | `*touka.Context` | Touka 框架上下文，包含请求和响应 |

### 返回值

无直接返回值。结果通过 `LoginResponse` 回调返回：

```go
// 默认 LoginResponse 格式
{
"code": 200,
"access_token": "<jwt>",
"refresh_token": "<random_token>",
"expire": "2024-01-01T12:00:00Z"
}
```

### 内部流程

1. 调用 `Authenticator(c)` 验证用户凭据
2. 若认证失败，调用 `unauthorized` 返回 401，**始终**设置 `WWW-Authenticate` 响应头；当 `DisabledAbort` 为 `false` 时会先 `Abort`
3. 调用 `TokenGenerator` 生成 token pair
4. 调用 `setAccessTokenCookie` 设置 access token cookie（内部检查 `SendCookie`，仅在 `SendCookie=true` 时写入）
5. 调用 `SetRefreshTokenCookie` 设置 refresh token cookie（内部检查 `SendCookie`，仅在 `SendCookie=true` 时写入）
6. 调用 `LoginResponse` 返回响应

### 使用示例

```go
package main

import (
    "net/http"
    "time"

    "filippo.io/mldsa"
    jwtmw "github.com/fenthope/jwt"
    "github.com/infinite-iroha/touka"
)

type loginRequest struct {
    Username string `form:"username" binding:"required"`
    Password string `form:"password" binding:"required"`
}

func main() {
    engine := touka.Default()

    privateKey, _ := mldsa.GenerateKey(mldsa.MLDSA65())

    auth, _ := jwtmw.New(&jwtmw.ToukaJWTMiddleware{
        Realm:           "test zone",
        Key:             privateKey,
        Timeout:         time.Hour,
        RefreshTokenTimeout: time.Hour * 24 * 7,
        Authenticator: func(c *touka.Context) (any, error) {
            var req loginRequest
            if err := c.ShouldBind(&req); err != nil {
                return nil, jwtmw.ErrMissingLoginValues
            }
            if req.Username == "admin" && req.Password == "admin" {
                return map[string]any{"user_id": req.Username}, nil
            }
            return nil, jwtmw.ErrFailedAuthentication
        },
        PayloadFunc: func(data any) jwtmw.MapClaims {
            if m, ok := data.(map[string]any); ok {
                return jwtmw.MapClaims{"identity": m["user_id"]}
            }
            return jwtmw.MapClaims{}
        },
    })

    engine.POST("/login", auth.LoginHandler)

    http.ListenAndServe(":8000", engine)
}
```

### 错误处理

| 错误 | HTTP 状态码 | 说明 |
|------|-------------|------|
| `ErrMissingAuthenticatorFunc` | 500 | 未设置 Authenticator |
| `Authenticator 返回 error` | 401 | 认证失败 |
| `ErrFailedTokenCreation` | 401 | token 生成或存储失败 |
| `ErrMissingPrivateKey` | 500 | 未配置签名密钥 |

---

## RefreshHandler

使用 refresh token 换取新的 token pair。执行 refresh token rotation。

### 函数签名

```go
func (mw *ToukaJWTMiddleware) RefreshHandler(c *touka.Context)
```

### 参数

| 参数 | 类型 | 说明 |
|------|------|------|
| c | `*touka.Context` | Touka 框架上下文 |

### 返回值

无直接返回值。结果通过 `RefreshResponse` 回调返回，格式同 `LoginHandler`。

### 内部流程

1. 按顺序从 cookie 或 form body（key 为 `RefreshTokenCookieName`，默认 `refresh_token`）提取 refresh token（`extractRefreshToken`）
2. 若未找到 refresh token，返回 400
3. 调用 `RefreshTokenManager.Lookup` 验证 refresh token 并获取关联的用户数据；若未配置 manager，则回退调用 `TokenStore.Get`
4. 若验证失败，返回 401
5. 标准化并验证 refresh token 状态；若配置了 `MaxRefresh`，会校验 `MaxRefreshUntil`
6. 调用 `generateTokenPair` 生成新 token pair
7. 调用 `rotateRefreshToken` 执行 refresh token rotation：
   - 若配置了 `RefreshTokenManager`，调用其 `Rotate`
   - 否则要求 store 实现 `RefreshTokenRotator` 接口，并调用兼容模式的原子 `Rotate`
   - 若兼容模式下未实现，则返回 `ErrUnsafeRefreshRotation`，HTTP 500
   - 若 `rotateRefreshToken` 返回 `ErrRefreshTokenNotFound` 或 `ErrRefreshTokenExpired`，按 401 处理
8. 新 token 的 `RefreshExpiresAt` 继承自旧 refresh token 状态的有效期上限，不会因为 refresh 而无限延长
8. 若 `SendCookie` 为 `true`，设置新的 access token 和 refresh token cookie
9. 调用 `RefreshResponse` 返回响应

### 使用示例

```go
engine.POST("/refresh_token", auth.RefreshHandler)
```

客户端使用 cookie 时：

```go
// 请求不需要带任何 body
// refresh token 从 cookie 自动读取
fetch("/refresh_token", {
    method: "POST",
    credentials: "include"  // 发送 cookie
})
```

客户端使用 form body 时（key 为 `RefreshTokenCookieName`，默认 `refresh_token`）：

```go
fetch("/refresh_token", {
method: "POST",
headers: {"Content-Type": "application/x-www-form-urlencoded"},
body: "refresh_token=xxx"
})
```

### 错误处理

| 错误 | HTTP 状态码 | 说明 |
|------|-------------|------|
| `ErrMissingRefreshToken` | 400 | 未提供 refresh token |
| `core.ErrRefreshTokenNotFound` | 401 | refresh token 不存在或已撤销 |
| `core.ErrRefreshTokenExpired` | 401 | refresh token 已过期，或超过 `MaxRefresh` 限制 |
| `ErrUnsafeRefreshRotation` | 500 | 未配置 `RefreshTokenManager` 且 `TokenStore` 未实现 `RefreshTokenRotator` |

---

## LogoutHandler

用户登出，并尽可能撤销 refresh token 链；若启用了 cookie，同时清除客户端 cookie。

### 函数签名

```go
func (mw *ToukaJWTMiddleware) LogoutHandler(c *touka.Context)
```

### 参数

| 参数 | 类型 | 说明 |
|------|------|------|
| c | `*touka.Context` | Touka 框架上下文 |

### 返回值

无直接返回值。结果通过 `LogoutResponse` 回调返回：

```go
// 默认 LogoutResponse 格式
{"code": 200}
```

### 内部流程

1. 按顺序从 cookie 或 form body 提取 refresh token
2. 若找到 refresh token，优先调用 `RefreshTokenManager.Revoke`
3. 未配置 manager 时，按当前进程内记录且仍未过期的 successor 链获取可撤销链。若 store 实现 `RefreshTokenRevoker` 接口，调用 `Revoke` 原子撤销整链；否则逐个 `Delete`
4. 删除过程中会忽略 `core.ErrRefreshTokenNotFound` 和 `core.ErrRefreshTokenExpired`
5. 若删除出现其他错误，返回 500
5. 若 `SendCookie` 为 true，清除 `CookieName` 和 `RefreshTokenCookieName` 对应的 cookie
6. 调用 `LogoutResponse` 返回响应

### 使用示例

```go
engine.POST("/logout", auth.LogoutHandler)
```

注意：若配置了 `RefreshTokenManager`，`LogoutHandler` 的撤销语义完全由该接口决定。未配置时，才会基于当前进程内记录的 refresh token successor 链删除相关 token，同时清除客户端 cookie。兼容模式下该链只沿仍未过期的 successor 映射继续追链；过期映射会被视为链路中断。该链不是持久化状态，也不是跨实例共享状态；如果只想清除 cookie 而不撤销 token，可以在调用 `LogoutHandler` 之前自行处理。

---

## MiddlewareFunc

JWT 验证中间件，提取并验证请求中的 access token。

### 函数签名

```go
func (mw *ToukaJWTMiddleware) MiddlewareFunc() touka.HandlerFunc
```

### 参数

无直接参数。返回一个 `touka.HandlerFunc` 供路由使用。

### 返回值

| 类型 | 说明 |
|------|------|
| `touka.HandlerFunc` | 中间件 handler 函数 |

### 内部流程

1. 调用 `GetClaimsFromJWT` -> `ParseToken` 提取并解析 JWT
2. 若解析失败，调用 `handleTokenError` 处理错误并终止
3. 验证 `exp` 字段：若缺失返回 400，若格式错误返回 400，若已过期返回 401
4. 将 claims 存入 `c.Set("JWT_PAYLOAD", claims)`
5. 调用 `IdentityHandler` 提取身份信息，存入 `c.Set(mw.IdentityKey, identity)`
6. 调用 `Authorizator` 验证授权，失败返回 403
7. 若 `SendAuthorization` 为 `true`，会在成功解析后回写响应头 `Authorization: <TokenHeadName> <token>`
8. 调用 `c.Next()` 继续处理链

### 使用示例

```go
engine := touka.Default()

privateKey, _ := mldsa.GenerateKey(mldsa.MLDSA65())

auth, _ := jwtmw.New(&jwtmw.ToukaJWTMiddleware{
    Realm: "test zone",
    Key:   privateKey,
    Authenticator: func(c *touka.Context) (any, error) {
        // ...
    },
})

// 作为中间件使用
authGroup := engine.Group("/api", auth.MiddlewareFunc())
authGroup.GET("/profile", func(c *touka.Context) {
    identity, _ := c.Get("identity")
    c.JSON(200, touka.H{"user": identity})
})
authGroup.GET("/protected", func(c *touka.Context) {
    c.JSON(200, touka.H{"message": "allowed"})
})
```

### 错误处理

| 错误 | HTTP 状态码 | 说明 |
|------|-------------|------|
| `ParseToken` 解析失败 | 401 | token 无效、签名不匹配、格式错误，或 JWT 库判定已过期/未生效 |
| `ErrMissingExpField` | 400 | token 缺少 exp 字段 |
| `ErrWrongFormatOfExp` | 400 | exp 字段格式错误 |
| `ErrForbidden` | 403 | `Authorizator` 返回 false |

### Token 提取位置

`TokenLookup` 配置决定从哪里提取 access token，格式为 `"source:name,source:name"`：

| source | 说明 | 示例 |
|--------|------|------|
| `header` | HTTP 头 | `header:Authorization` |
| `query` | URL query 参数 | `query:token` |
| `cookie` | Cookie | `cookie:jwt` |
| `param` | 路径参数 | `param:token` |
| `form` | POST form body | `form:token` |

默认值为 `"header:Authorization"`，即从 `Authorization: Bearer <token>` 头提取。

---

## ParseToken

解析请求中的 JWT token。

### 函数签名

```go
func (mw *ToukaJWTMiddleware) ParseToken(c *touka.Context) (*jwt.Token, error)
```

### 参数

| 参数 | 类型 | 说明 |
|------|------|------|
| c | `*touka.Context` | Touka 框架上下文 |

### 返回值

| 类型 | 说明 |
|------|------|
| `*jwt.Token` | 解析后的 JWT token 对象 |
| `error` | 解析失败时的错误 |

### 内部流程

1. 根据 `TokenLookup` 配置依次尝试从各位置提取 token
2. 若所有位置都未找到 token，返回 `ErrEmptyAuthHeader`
3. 调用 `jwt.Parse` 验证 token：
    - 检查算法是否与配置匹配
    - 若设置 `KeyFunc` 则调用它获取密钥，否则使用 `verifyKey`
4. 解析时总是附带 `jwt.WithTimeFunc(mw.TimeFunc)`，并追加 `ParseOptions`
5. 验证通过后，将 raw token 存入 `c.Set("JWT_TOKEN", token)`
6. 返回解析后的 token

### 使用示例

```go
engine.GET("/verify", func(c *touka.Context) {
    token, err := auth.ParseToken(c)
    if err != nil {
        c.JSON(401, touka.H{"error": err.Error()})
        return
    }

    claims := jwtmw.ExtractClaimsFromToken(token)
    c.JSON(200, touka.H{
        "claims": claims,
        "header": token.Header,
    })
})
```

### 辅助函数

```go
// 从 context 中提取 JWT claims
func ExtractClaims(c *touka.Context) jwt.MapClaims

// 从 token 对象提取 claims
func ExtractClaimsFromToken(token *jwt.Token) jwt.MapClaims

// 获取原始 JWT token 字符串
func GetToken(c *touka.Context) string
```

### 错误处理

| 错误 | 说明 |
|------|------|
| `ErrEmptyAuthHeader` | 未找到 token |
| `ErrInvalidSigningAlgorithm` | 算法不匹配 |
| `jwt.ErrTokenExpired` | token 已过期 |
| `jwt.ErrTokenNotValidYet` | token 尚未生效 |
| `jwt.ErrTokenMalformed` | token 格式错误 |

---

## 初始化与配置

### New 函数

```go
func New(mw *ToukaJWTMiddleware) (*ToukaJWTMiddleware, error)
```

创建并初始化中间件。内部调用 `MiddlewareInit`，验证配置、加载密钥、设置默认值。

### 默认值

| 字段 | 默认值 |
|------|--------|
| `SigningAlgorithm` | `ML-DSA-65` |
| `Timeout` | `1 hour` |
| `TimeoutFunc` | `func(data any) time.Duration { return mw.Timeout }` |
| `RefreshTokenTimeout` | `7 days`（或 `MaxRefresh`） |
| `IdentityKey` | `identity` |
| `TokenHeadName` | `Bearer` |
| `TokenLookup` | `header:Authorization` |
| `CookieName` | `jwt` |
| `RefreshTokenCookieName` | `refresh_token` |
| `RefreshTokenSecureCookie` | 当 `SendCookie` 为 `true` 时被设置为 `true` |
| `RefreshTokenCookieHTTPOnly` | 当 `SendCookie` 为 `true` 时被设置为 `true` |
| `TimeFunc` | `time.Now` |
| `ExpField` | `"exp"` |
| `Authorizator` | 始终返回 true |
| `IdentityHandler` | 从 `JWT_PAYLOAD[mw.IdentityKey]` 读取身份 |
| `HTTPStatusMessageFunc` | `error == nil` 时返回空字符串，否则返回 `error.Error()` |
| `TokenStore` | `store.NewInMemoryRefreshTokenStoreWithClock(mw.TimeFunc)` |
| `Unauthorized` | 返回 JSON `{"code": <code>, "message": <message>}` |
| `LoginResponse` | 返回 JSON 包含 access_token, refresh_token, expire |
| `RefreshResponse` | 同 LoginResponse |
| `LogoutResponse` | 返回 JSON `{"code": <code>}` |

### 完整示例

```go
package main

import (
    "net/http"
    "time"

    "filippo.io/mldsa"
    jwtmw "github.com/fenthope/jwt"
    "github.com/infinite-iroha/touka"
)

type User struct {
    UserName string
}

func main() {
    engine := touka.Default()

    privateKey, _ := mldsa.GenerateKey(mldsa.MLDSA65())

    auth, err := jwtmw.New(&jwtmw.ToukaJWTMiddleware{
        Realm:              "test zone",
        Key:                privateKey,
        Timeout:            time.Hour,
        RefreshTokenTimeout: time.Hour * 24 * 7,
        IdentityKey:        "id",
        Authenticator: func(c *touka.Context) (any, error) {
            var req struct {
                Username string `form:"username"`
                Password string `form:"password"`
            }
            c.ShouldBind(&req)
            if req.Username == "admin" && req.Password == "admin" {
                return &User{UserName: req.Username}, nil
            }
            return nil, jwtmw.ErrFailedAuthentication
        },
        PayloadFunc: func(data any) jwtmw.MapClaims {
            if u, ok := data.(*User); ok {
                return jwtmw.MapClaims{"id": u.UserName}
            }
            return jwtmw.MapClaims{}
        },
        IdentityHandler: func(c *touka.Context) any {
            claims := jwtmw.ExtractClaims(c)
            return &User{UserName: claims["id"].(string)}
        },
        Authorizator: func(data any, c *touka.Context) bool {
            if u, ok := data.(*User); ok {
                return u.UserName == "admin"
            }
            return false
        },
    })
    if err != nil {
        panic(err)
    }

    // 公开路由
    engine.POST("/login", auth.LoginHandler)
    engine.POST("/refresh_token", auth.RefreshHandler)

    // 受保护路由
    authGroup := engine.Group("", auth.MiddlewareFunc())
    authGroup.GET("/profile", func(c *touka.Context) {
        user, _ := c.Get("id")
        c.JSON(200, touka.H{"user": user})
    })

    http.ListenAndServe(":8000", engine)
}
```

---

## 错误常量

| 错误 | 说明 |
|------|------|
| `ErrMissingRealm` | 未设置 Realm |
| `ErrMissingSecretKey` | 未配置密钥 |
| `ErrForbidden` | 无访问权限 |
| `ErrMissingAuthenticatorFunc` | 未设置 Authenticator |
| `ErrMissingExpField` | token 缺少 exp 字段 |
| `ErrWrongFormatOfExp` | exp 字段格式错误 |
| `ErrInvalidSigningAlgorithm` | 不支持的签名算法 |
| `ErrInvalidPrivKey` | 无效的私钥 |
| `ErrInvalidPubKey` | 无效的公钥 |
| `ErrEmptyAuthHeader` | 认证头为空 |
| `ErrInvalidAuthHeader` | 错误常量已定义，但当前 `ParseToken` 实现不会直接返回它；header 不匹配时会继续尝试其他来源，全部失败后统一返回 `ErrEmptyAuthHeader` |
| `ErrEmptyQueryToken` | 错误常量已定义，但当前实现不会直接返回它 |
| `ErrEmptyCookieToken` | 错误常量已定义，但当前实现不会直接返回它 |
| `ErrEmptyParamToken` | 错误常量已定义，但当前实现不会直接返回它 |
| `ErrFailedAuthentication` | 认证失败（用户名或密码错误） |
| `ErrMissingLoginValues` | 缺少登录凭据 |
| `ErrFailedTokenCreation` | token 创建失败 |
| `ErrMissingPrivateKey` | 缺少私钥 |
| `ErrExpiredToken` | token 已过期 |
| `ErrMissingRefreshToken` | 缺少 refresh token |
| `ErrUnsafeRefreshRotation` | refresh token rotation 要求 store 实现 `RefreshTokenRotator` |
| `ErrInvalidTokenLookup` | 无效的 token lookup 配置 |
