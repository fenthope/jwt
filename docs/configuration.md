# 配置参考

本文档详细说明 ToukaJWTMiddleware 的所有配置项。

## 完整配置表

| 配置项 | 类型 | 默认值 | 必需 | 说明 |
|--------|------|--------|------|------|
| `Realm` | `string` | 无 | 是 | 认证域名称，用于 `WWW-Authenticate` 响应头。缺少时中间件初始化失败 |
| `SigningAlgorithm` | `string` | `"ML-DSA-65"` | 否 | 签名算法名称。支持内置 `ML-DSA-65`，或通过 `RegisterAlgorithm` 注册的自定义算法 |
| `Key` | `any` | 无 | 否 | 直接传入算法所需的签名密钥对象。类型取决于 `SigningAlgorithm`：使用 `ML-DSA-65` 时为 `*mldsa.PrivateKey` |
| `KeyFunc` | `func(token *jwt.Token) (any, error)` | 无 | 否 | 自定义密钥解析函数。用于在运行时动态确定验签密钥。若未设置，则使用 `verifyKey` |
| `Timeout` | `time.Duration` | `time.Hour` | 否 | Access Token 有效期。`TimeoutFunc` 未设置时作为默认过期时长 |
| `TimeoutFunc` | `func(data any) time.Duration` | 返回 `Timeout` 值 | 否 | 根据用户数据动态计算 Token 过期时长。用于实现不同用户不同过期时间 |
| `MaxRefresh` | `time.Duration` | 无（零值） | 否 | Refresh Token 最大可刷新时间窗口。超过该时间后 Refresh Token 失效 |
| `RefreshTokenTimeout` | `time.Duration` | 若未设置：若 `MaxRefresh` 非零则为 `MaxRefresh`，否则 `time.Hour * 24 * 7` | 否 | Refresh Token 实际有效期 |
| `Authenticator` | `func(c *touka.Context) (any, error)` | 无 | 否* | 登录认证函数。接收请求上下文，返回用户标识数据。`LoginHandler` 必需此函数 |
| `PayloadFunc` | `func(data any) MapClaims` | 无 | 否 | 自定义 Claims 填充函数。接收 `Authenticator` 返回的数据，返回要写入 Token 的 Claims |
| `IdentityHandler` | `func(c *touka.Context) any` | 从 Claims 提取 `IdentityKey` | 否 | 从已解析的 Claims 中提取用户身份。默认使用 `IdentityKey` 字段名从 Claims 中取值 |
| `IdentityKey` | `string` | `"identity"` | 否 | 用户身份在 Claims 中的字段名 |
| `Authorizator` | `func(data any, c *touka.Context) bool` | 始终返回 `true` | 否 | 授权检查函数。接收用户身份数据和上下文，返回是否授权通过 |
| `Unauthorized` | `func(c *touka.Context, code int, message string)` | JSON 返回 `{"code": <code>, "message": <message>}` | 否 | 认证/授权失败时的响应处理函数 |
| `LoginResponse` | `func(c *touka.Context, code int, token *core.Token)` | JSON 返回 `{"code": <code>, "access_token": <token>, "refresh_token": <token>, "expire": <RFC3339>}` | 否 | 登录成功后的响应处理函数 |
| `LogoutResponse` | `func(c *touka.Context, code int)` | JSON 返回 `{"code": <code>}` | 否 | 登出成功后的响应处理函数 |
| `RefreshResponse` | `func(c *touka.Context, code int, token *core.Token)` | JSON 返回 `{"code": <code>, "access_token": <token>, "refresh_token": <token>, "expire": <RFC3339>}` | 否 | Token 刷新成功后的响应处理函数 |
| `HTTPStatusMessageFunc` | `func(e error, c *touka.Context) string` | 返回 `e.Error()` | 否 | 将错误转换为 HTTP 响应消息的函数 |
| `TokenLookup` | `string` | `"header:Authorization"` | 否 | Access Token 提取位置。格式为 `"source:key"`，多个源用逗号分隔。source 可选：`header`、`query`、`cookie`、`param`、`form` |
| `TokenHeadName` | `string` | `"Bearer"` | 否 | Authorization Header 前缀名。用于从 Header 提取 Token 时匹配前缀 |
| `TimeFunc` | `func() time.Time` | `time.Now` | 否 | 获取当前时间的函数。用于 Token 签发和过期计算 |
| `ExpField` | `string` | `"exp"` | 否 | Token 过期时间戳在 Claims 中的字段名 |
| `SendCookie` | `bool` | `false` | 否 | 是否将 Access Token 和 Refresh Token 写入 Cookie |
| `CookieName` | `string` | `"jwt"` | 否 | Access Token Cookie 名称 |
| `CookieMaxAge` | `time.Duration` | 无 | 否 | Cookie 最大存活时间。优先使用 `CookieMaxAge`；若未设置或 `<=0`，则回退到 `Timeout` |
| `CookieDomain` | `string` | 空字符串 | 否 | Cookie 所属域名 |
| `SecureCookie` | `bool` | `false` | 否 | Access Token Cookie 是否仅通过 HTTPS 发送 |
| `CookieHTTPOnly` | `bool` | `false` | 否 | Access Token Cookie 是否禁止 JavaScript 访问 |
| `CookieSameSite` | `http.SameSite` | `0`（`http.SameSiteDefaultMode`） | 否 | Cookie 的 SameSite 属性。`0` 时框架不设置该属性 |
| `RefreshTokenCookieName` | `string` | `"refresh_token"` | 否 | Refresh Token Cookie 名称 |
| `RefreshTokenSecureCookie` | `bool` | `false`（`SendCookie=true` 时为 `true`） | 否 | Refresh Token Cookie 是否仅通过 HTTPS 发送 |
| `RefreshTokenCookieHTTPOnly` | `bool` | `false`（`SendCookie=true` 时为 `true`） | 否 | Refresh Token Cookie 是否禁止 JavaScript 访问 |
| `PrivKeyFile` | `string` | 无 | 否 | 算法签名密钥文件路径。文件内容为算法所需的原始字节（`ML-DSA-65` 为 32 字节 seed） |
| `PrivKeyBytes` | `[]byte` | 无 | 否 | 算法签名密钥字节数组。与 `PrivKeyFile` 二选一 |
| `PubKeyFile` | `string` | 无 | 否 | 算法验签公钥文件路径。文件内容为算法所需的原始字节（`ML-DSA-65` 为 `mldsa.PublicKey.Bytes()` 输出） |
| `PubKeyBytes` | `[]byte` | 无 | 否 | 算法验签公钥字节数组。与 `PubKeyFile` 二选一 |
| `ParseOptions` | `[]jwt.ParserOption` | 无 | 否 | JWT 解析选项，透传给 `jwt.Parse` |
| `SendAuthorization` | `bool` | `false` | 否 | 是否在响应 Header 中回传 Authorization 头 |
| `TokenStore` | `core.TokenStore` | 内存存储 (`InMemoryRefreshTokenStore`) | 否 | Refresh Token 存储接口实现。若要支持 `RefreshHandler`，store 必须实现 `core.RefreshTokenRotator` |
| `DisabledAbort` | `bool` | `false` | 否 | 认证失败后是否阻止后续 Handler 执行。`true` 时不调用 `c.Abort()` |

## 密钥配置说明

### ML-DSA-65（默认算法）

使用默认 `ML-DSA-65` 算法时，密钥配置方式如下：

| 配置项 | 格式要求 |
|--------|----------|
| `Key` | `*mldsa.PrivateKey` |
| `PrivKeyBytes` / `PrivKeyFile` | 原始 32 字节 seed |
| `PubKeyBytes` / `PubKeyFile` | `mldsa.PublicKey.Bytes()` 输出 |

> 注意：以上均为原始字节，不是 PEM 编码也不是 PKCS#8 格式。

### 密钥优先级

1. `Key`（最高优先）
2. `PrivKeyBytes` / `PubKeyBytes`
3. `PrivKeyFile` / `PubKeyFile`
4. 从 `Key` 派生（仅公钥）

若使用公钥验签模式（Verify-Only），只需提供 `PubKeyBytes` 或 `PubKeyFile`，此时 `LoginHandler` 和 `RefreshHandler` 会因缺少私钥而失败。

## TokenLookup 格式

格式：`source:key_name`

source 可选值：

| source | 说明 |
|--------|------|
| `header` | 从请求头提取 |
| `query` | 从 URL 查询参数提取 |
| `cookie` | 从 Cookie 提取 |
| `param` | 从路径参数提取 |
| `form` | 从表单 body 提取 |

多源配置示例：`"header:Authorization,query:token"`

## 响应函数签名

| 函数 | 签名 |
|------|------|
| `Unauthorized` | `func(c *touka.Context, code int, message string)` |
| `LoginResponse` | `func(c *touka.Context, code int, token *core.Token)` |
| `LogoutResponse` | `func(c *touka.Context, code int)` |
| `RefreshResponse` | `func(c *touka.Context, code int, token *core.Token)` |

`core.Token` 结构体：

```go
type Token struct {
	AccessToken       string `json:"access_token"`
	TokenType         string `json:"token_type"`
	RefreshToken      string `json:"refresh_token,omitempty"`
	ExpiresAt         int64  `json:"expires_at"`         // Unix 时间戳
	CreatedAt         int64  `json:"created_at"`
	RefreshExpiresAt  int64  `json:"refresh_expires_at,omitempty"` // Unix 时间戳
}
```

> 注意：默认 `LoginResponse` / `RefreshResponse` 中的 `"expire"` 字段是 `ExpiresAt` 转换的 RFC3339 格式字符串，**不是** 直接返回 `expires_at` 字段。`ExpiresIn` 不是结构体字段，而是通过 `Token.ExpiresIn()` 方法计算。`ExpiresIn()` 返回 `ExpiresAt - time.Now().Unix()`（剩余秒数）。

## 配置示例

### 最小配置

```go
mw := &jwtmw.ToukaJWTMiddleware{
    Realm: "test zone",
    Key:   privateKey,
}
```

### 完整配置

```go
mw := &jwtmw.ToukaJWTMiddleware{
    Realm:              "test zone",
    SigningAlgorithm:   "ML-DSA-65",
    Key:                privateKey,
    Timeout:            time.Hour,
    MaxRefresh:         7 * 24 * time.Hour,
    Authenticator: func(c *touka.Context) (any, error) {
        return "admin", nil
    },
    PayloadFunc: func(data any) jwtmw.MapClaims {
        return jwtmw.MapClaims{"identity": data}
    },
    IdentityHandler: func(c *touka.Context) any {
        return ExtractClaims(c)["identity"]
    },
    Authorizator: func(data any, c *touka.Context) bool {
        return data == "admin"
    },
    Unauthorized: func(c *touka.Context, code int, message string) {
        c.JSON(code, touka.H{"error": message})
    },
    LoginResponse: func(c *touka.Context, code int, token *core.Token) {
        c.JSON(code, token)
    },
    TokenLookup:    "header:Authorization",
    TokenHeadName:  "Bearer",
    SendCookie:     true,
    CookieName:     "jwt",
    CookieDomain:   "example.com",
    SecureCookie:   true,
    CookieHTTPOnly: true,
}
```
