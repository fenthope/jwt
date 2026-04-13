# Touka JWT Middleware 安全最佳实践

本文档面向使用 Touka JWT Middleware 构建生产系统的开发者，涵盖从密钥管理到 Cookie 配置的完整安全建议。

---

## 1. Token 安全

### 1.1 ML-DSA-65 密钥生成和存储

ML-DSA-65 是基于格密码的后量子签名算法，比传统 HMAC 或 RSA 有更强的安全性储备。生成密钥时必须使用加密安全的随机源：

```go
import "filippo.io/mldsa"

privateKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
if err != nil {
    panic(err)
}
```

**存储要求**：

- 私钥文件权限应限制为 `0600`，属主仅运行进程的用户
- 私钥不应写入代码仓库或日志
- 推荐使用文件路径 `PrivKeyFile` 加载，而非 `PrivKeyBytes`，后者会将密钥载入进程内存长青树

```go
mw := &jwtmw.ToukaJWTMiddleware{
    PrivKeyFile: "/run/secrets/jwt_private_key", // 文件内容为32字节seed
}
```

### 1.2 避免弱密钥

不要使用以下类型的密钥：

| 类型 | 风险 |
|------|------|
| 硬编码字符串如 `"secret"` 或 `"password"` | 可被暴力穷举 |
| 生日、姓名等低熵内容 | 字典攻击 |
| 过短的密钥 | ML-DSA-65 要求至少 32 字节 seed |
| 重复使用的密钥 | 一旦泄露影响范围大 |

ML-DSA-65 的 32 字节 seed 由 `crypto/rand` 生成，确保熵源足够。

### 1.3 密钥轮换

长期使用的密钥应定期轮换。轮换策略：

1. **共存期轮换**：新私钥上线后，保留旧私钥验证能力一段时间，通过 `KeyFunc` 动态判断使用哪个密钥：

```go
mw := &jwtmw.ToukaJWTMiddleware{
    KeyFunc: func(token *jwt.Token) (any, error) {
        // 根据 token 的 kid 或其他标识选择对应版本的密钥
        kid := token.Header["kid"]
        switch kid {
        case "v2":
            return v2PublicKey, nil
        default:
            return v1PublicKey, nil
        }
    },
}
```

2. **宽限期设置**：旧密钥验证能力保留至少一个 token 生命周期（通常 7-30 天）

3. **轮换记录**：维护密钥版本日志，便于安全审计

---

## 2. Refresh Token 安全

### 2.1 为什么不应该放在 URL 里

Refresh token 是长期 bearer secret，放在 URL 中存在以下风险：

- **日志泄露**：URL 会写入 Web 服务器日志、代理日志、浏览器历史、Referer 头
- **浏览器地址栏暴露**：页面截图、分享链接时无意泄露
- **Referer 头传递**：跳转到第三方页面时自动携带完整 URL
- **缓存污染**：代理服务器可能缓存包含 token 的 URL

Touka JWT Middleware 的 `extractRefreshToken` 方法（`auth_jwt.go:662-670`）明确只从 cookie 和 form body 提取 token，不从 query string 读取，这是正确的设计。

### 2.2 Cookie + Form 的提取方式

Refresh token 提取顺序（`auth_jwt.go:662-670`）：

```go
func (mw *ToukaJWTMiddleware) extractRefreshToken(c *touka.Context) string {
    if token, _ := c.GetCookie(mw.RefreshTokenCookieName); token != "" {
        return token
    }
    if token := c.PostForm(mw.RefreshTokenCookieName); token != "" {
        return token
    }
    return ""
}
```

**推荐配置**：

- 优先使用 **Cookie** 传输 refresh token，配合 `SecureCookie: true` 和 `CookieHTTPOnly: true`
- Form body 方式适用于不支持 Cookie 的场景（如移动端原生应用），但应配合 HTTPS
- 不要同时在 URL query string 中传递 refresh token

### 2.3 Refresh Rotation 的原子性

Refresh token rotation 是指每次 refresh 时颁发新 token 并使旧 token 失效。这能限制被盗 token 的有效期。

Touka JWT Middleware 的处理逻辑（`auth_jwt.go:514-548`）：

```go
func (mw *ToukaJWTMiddleware) rotateRefreshToken(ctx context.Context, oldToken, newToken string, userData any) error {
	unlock := acquireRefreshTokenLock(oldToken)
	defer unlock()
	currentToken, err := mw.TokenStore.Get(ctx, oldToken)
	if err != nil {
		return err
	}
	currentToken = mw.normalizeRefreshTokenState(currentToken)
	if currentToken == nil {
		return core.ErrRefreshTokenNotFound
	}
	if err := mw.validateRefreshTokenState(currentToken); err != nil {
		return err
	}
	expiry := mw.refreshTokenExpiry(currentToken)
	if rotator, ok := mw.TokenStore.(core.RefreshTokenRotator); ok {
		if err := rotator.Rotate(ctx, oldToken, newToken, currentToken, expiry); err != nil {
			return err
		}
		setRefreshTokenSuccessor(oldToken, newToken)
		return nil
	}
	return ErrUnsafeRefreshRotation
}
```

**关键要求**：refresh token rotation 必须是原子的。中间件不再接受非原子的 `Set(new) -> Delete(old)` 回退流程，因为这会产生新旧 token 同时有效的窗口。

**推荐做法**：TokenStore 实现 `core.RefreshTokenRotator` 接口，提供原子 `Rotate` 操作。内置的 `InMemoryRefreshTokenStore` 已实现此接口（`store/memory.go:13`）。如果自定义 store 未实现该接口，`RefreshHandler` 会直接拒绝 refresh 请求。

### 2.4 长期 Token 的风险

Refresh token 本质是长期 bearer secret，风险随时间累积：

- **被动泄露**：即使 HTTPS 加密，token 仍存储在客户端，可能被 XSS 盗取
- **主动攻击**：CSRF 攻击在用户不知情时使用已登录状态发起 refresh 请求
- **密钥泄露**：长期 token 的安全性依赖初始签发时的密钥，密钥泄露意味着所有历史 token 失效

**缓解措施**：

- 设定 refresh token 最大有效期（`RefreshTokenTimeout`），建议不超过 30 天
- 记录 refresh token 使用的 IP、User-Agent，异常时拒绝 rotation
- 实现 token 撤销机制，支持主动使旧 token 失效

---

## 3. Cookie 安全配置

### 3.1 SecureCookie

`SecureCookie: true` 要求浏览器仅通过 HTTPS 连接发送 Cookie。**生产环境必须开启**。

```go
SecureCookie: true, // 启用后仅 HTTPS 传输
```

未启用时，在 HTTP 明文传输环境下，Cookie 内容可被中间人攻击窃取。

本地开发如果使用 HTTP，临时将此值设为 `false`，但必须确保生产环境为 `true`。

### 3.2 CookieHTTPOnly

`CookieHTTPOnly: true` 防止 JavaScript 通过 `document.cookie` 读取 Cookie。**必须开启**。

```go
RefreshTokenCookieHTTPOnly: true,  // 启用后 JS 无法访问
```

这是对抗 XSS 攻击的核心防线。即使攻击者能在页面执行 JS，也无法直接获取 refresh token。

注意：当 `SendCookie: true` 时，Touka JWT Middleware 仅针对 **RefreshToken cookie** 自动设置 `RefreshTokenSecureCookie: true` 和 `RefreshTokenCookieHTTPOnly: true`（`auth_jwt.go:165-168`）。普通 access token cookie 的 `SecureCookie` 和 `CookieHTTPOnly` 不会被自动设置，如需启用请手动配置。

### 3.3 CookieSameSite

`CookieSameSite` 防止 CSRF 攻击。建议配置：

```go
CookieSameSite: http.SameSiteStrictMode,
```

| 值 | 行为 | 适用场景 |
|----|------|----------|
| `SameSiteStrictMode` | 完全禁止跨站请求携带 cookie | 高安全性场景 |
| `SameSiteLaxMode` | 导航请求（如跳转链接）允许携带，POST表单等不允许 | 需要从外部链接回来的场景 |
| `SameSiteNoneMode` | 允许跨站，但必须配合 `SecureCookie: true` | API 调用、SPA 前后端分离 |

**警告**：`SameSiteNoneMode` 必须在 `SecureCookie: true` 时使用，否则浏览器会拒绝设置 cookie。

### 3.4 CookieDomain

`CookieDomain` 控制 cookie 的有效域名范围：

```go
CookieDomain: ".example.com",  // 包含所有子域名
// 或
CookieDomain: "api.example.com",  // 仅限特定子域
```

**安全考量**：

- 尽量收窄范围，仅设置必要的子域
- 不要将 cookie 设置到不可控的父域名
- 子域入侵（如 `evil.example.com` 被攻陷）可以获取父域的 cookie 时，避免在父域设置敏感 cookie

---

## 4. 生产环境清单

### 4.1 HTTPS 要求

- **强制 HTTPS**：所有生产环境流量必须使用 HTTPS，HTTP 重定向到 HTTPS
- **HSTS 头**：配置 `Strict-Transport-Security`，建议 `max-age=31536000; includeSubDomains`
- **证书**：使用受信任 CA 签发的证书，避免自签名
- **TLS 版本**：最低 TLS 1.2，禁用 TLS 1.0/1.1 和 SSLv3
- **Cipher suite**：配置前向保密（Forward Secrecy）cipher，如 ECDHE 系列

```go
// 示例：nginx 配置
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

### 4.2 密钥管理

| 检查项 | 要求 |
|--------|------|
| 私钥存储位置 | 独立于代码仓库，放在受限目录如 `/run/secrets/` 或密钥管理服务 |
| 私钥文件权限 | `0600`，属主为运行进程的用户 |
| 私钥访问审计 | 日志记录密钥文件的访问尝试 |
| 密钥轮换机制 | 支持多版本密钥共存，旧密钥有明确退役计划 |
| 备份加密 | 密钥备份必须加密存储，备份介质物理安全 |

生产环境推荐方案：

- **云 KMS**：AWS KMS、Azure Key Vault、GCP Cloud KMS
- **HashiCorp Vault**：开源方案，支持动态密钥和审计
- **Kubernetes Secret**：配合加密存储使用

### 4.3 Token 过期时间建议

| Token 类型 | 建议过期时间 | 说明 |
|------------|--------------|------|
| Access Token | 15 分钟 - 1 小时 | 短期token，泄露窗口小 |
| Refresh Token | 1 天 - 30 天 | 取决于安全需求，更短更安全 |

```go
mw := &jwtmw.ToukaJWTMiddleware{
    Timeout:            time.Minute * 15,    // access token 15分钟
    RefreshTokenTimeout: time.Hour * 24 * 7, // refresh token 7天
}
```

**调整依据**：

- 用户活跃度高的应用：Access token 可以短一些（如 15 分钟）
- 移动端或网络不稳定场景：适当延长，但不超过 2 小时
- 高安全要求场景：缩短 refresh token 有效期，增加 refresh 频率

### 4.4 监控和日志

**必须记录的 Events**：

| 事件 | 记录内容 |
|------|----------|
| Login success | 时间戳、用户标识、IP、User-Agent |
| Login failure | 时间戳、尝试的用户名、IP、User-Agent、失败原因 |
| Token refresh | 时间戳、用户标识、旧token指纹（不记录完整token）、新token指纹、IP |
| Refresh failure | 时间戳、token指纹、失败原因、IP |
| Logout | 时间戳、用户标识、IP |

**告警阈值**：

- 同一IP 5分钟内失败登录超过 10 次
- 同一账户 1 小时内 refresh 次数超过正常业务量的 3 倍
- 来自异常地理位置的 refresh 请求

**禁止记录的内容**：

- 完整的 token 内容
- 用户密码或哈希值
- 私钥或 session secret

**日志保留**：安全日志至少保留 1 年，满足合规要求。

---

## 5. 快速参考配置

```go
mw := &jwtmw.ToukaJWTMiddleware{
    Realm: "production",

    // 密钥：必须从安全存储加载
    PrivKeyFile: "/run/secrets/jwt_private_key",
    PubKeyFile:  "/run/secrets/jwt_public_key",

    // Token 过期时间
    Timeout:            time.Minute * 15,
    RefreshTokenTimeout: time.Hour * 24 * 7,

// Cookie 安全配置
SendCookie: true,
// 当 SendCookie: true 时，RefreshTokenSecureCookie 和 RefreshTokenCookieHTTPOnly 会自动设为 true，
// 以下两行可省略（此处仅为明确展示完整配置）
RefreshTokenSecureCookie: true, // 已自动设置，此处显式声明
RefreshTokenCookieHTTPOnly: true, // 已自动设置，此处显式声明
CookieHTTPOnly: true,
SecureCookie: true, // 生产环境必须为 true
CookieSameSite: http.SameSiteStrictMode,

    // Store 配置
    TokenStore: myProductionTokenStore, // 替换默认内存 store
}
```
