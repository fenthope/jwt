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
- 推荐把密钥放在受限权限的外部文件或 secret 挂载中，再通过 `PrivKeyFile` 加载，以减少源码、环境变量和部署清单中的暴露面；但要注意，当前实现读取文件后仍会把密钥材料加载到进程内存中用于签名

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

Touka JWT Middleware 的 `extractRefreshToken` 只从 refresh token cookie 和同名 form 字段提取 token，不从 header、query string、path param 读取。这避免了把长期 bearer secret 暴露到 URL 或通用认证头。

### 2.2 Cookie + Form 的提取方式

Refresh token 提取顺序（`auth_jwt.go`）：

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

实现语义：

- 优先读取 `RefreshTokenCookieName` 对应的 cookie
- 只有 cookie 为空时，才读取同名 `POST form` 字段
- 不会复用 `TokenLookup` 的 access token 提取规则；即使 access token 配成从 header/query/cookie 读取，refresh token 仍然只走 cookie/form

**推荐配置**：

- 优先使用专用 refresh token cookie，配合 `RefreshTokenSecureCookie: true` 和 `RefreshTokenCookieHTTPOnly: true`
- Form body 方式适用于不支持 Cookie 的场景（如移动端原生应用），但应配合 HTTPS
- 不要同时在 URL query string 中传递 refresh token

### 2.3 Refresh Rotation 的原子性

Refresh token rotation 是指每次 refresh 时颁发新 token 并使旧 token 失效。这能限制被盗 token 的有效期。

Touka JWT Middleware 的处理逻辑（`auth_jwt.go`）有几个关键点：

- `RefreshHandler` 在生成新 token 前，会先 `Get` 一次旧 refresh token 并校验状态
- `rotateRefreshToken` 会对 `oldToken` 获取进程内互斥锁后，对 `oldToken` 执行 `Get` 并再次校验状态；整个流程中 `Get` 调用发生两次（`RefreshHandler` 入口一次、`rotateRefreshToken` 内部一次），结合持锁校验，避免同进程并发 refresh 直接复用同一个旧 token
- 只有 `TokenStore` 实现了 `core.RefreshTokenRotator` 时才允许轮换；否则直接返回 `ErrUnsafeRefreshRotation`
- 中间件不做 `Set(new) -> Delete(old)` 之类的非原子回退，也没有“先写新 token、失败再回滚”的补救路径；原子性完全由 store 的 `Rotate` 保证

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
		setRefreshTokenSuccessor(oldToken, newToken, expiry, mw.TimeFunc())
		return nil
	}
	return ErrUnsafeRefreshRotation
}
```

**失败语义**：

- `Rotate` 返回 `ErrRefreshTokenNotFound` 或 `ErrRefreshTokenExpired` 时，refresh 请求按未授权处理，客户端不得假设旧 token 仍可继续安全使用
- `Rotate` 返回其他错误时，refresh 请求按服务端错误处理；中间件不会发送新 cookie，也不会把新 token 返回给客户端
- 因为新 token 在成功轮换前不会对客户端可见，所以中间件侧不存在需要额外“回滚已发放 token”的步骤

**推荐做法**：TokenStore 必须实现 `core.RefreshTokenRotator`，并让 `Rotate` 在底层存储中以单个原子事务/脚本/条件更新完成“验证旧 token 仍有效、删除旧 token、写入新 token”。内置的 `InMemoryRefreshTokenStore` 已实现该接口；自定义 store 未实现该接口时，`RefreshHandler` 会直接拒绝 refresh 请求。

### 2.4 锁、状态校验与注销链路

当前实现不仅在 refresh 时加锁，还维护了一个进程内 successor 链：旧 refresh token 轮换成功后，会记录 `old -> new` 映射；`LogoutHandler` 会从当前 refresh token 开始，沿着这条链删除后继 token，尽量覆盖同一进程内发生过的连续轮换。

当底层 store 实现 `core.RefreshTokenRevoker` 时，middleware 会把整条已知链作为一个批次交给 `Revoke`。该接口的契约是：要么整批 token 一次性失效，要么返回错误；并且 logout 语义要求该操作对“已不存在/已过期”的 token 保持幂等。也就是说，`Revoke` 若返回 `ErrRefreshTokenNotFound` 或 `ErrRefreshTokenExpired`，应表示这一批 token 已经整体不可用，而不是只表示其中某一个 token 删除失败。

这带来以下安全语义：

- 同进程并发 refresh：`oldToken` 上的互斥锁能序列化 `rotateRefreshToken`
- refresh 时的 `MaxRefreshUntil` 会在进入 handler 后校验一次，在持锁轮换时再校验一次，避免并发窗口绕过过期判断
- logout 只会沿着当前进程内记住的 successor 链继续删除；如果链信息不存在，logout 只删除当前提交上来的 refresh token
- logout 只会沿着当前进程内仍然存在且未过期的 successor 映射继续删除；过期映射会被视为链路中断并在读取时惰性清理
- 实现了 `RefreshTokenRevoker` 的 store 可以把“当前 token 以及已知 successor 链的删除”下推为一次原子撤销；若未实现，则 middleware 退回逐个 `Delete`
- successor 链仅用于后续 logout 清理，不参与 refresh 鉴权；真正决定 refresh 是否成功的仍是 store 中旧 token 的存在性、过期时间和 `MaxRefreshUntil`

### 2.5 多实例与非原子轮换风险

当前实现对多实例部署的安全边界需要明确说明：

- `acquireRefreshTokenLock` 和 successor 链都是进程内内存结构，不会在多个应用实例之间共享
- 因此，多实例部署时，跨实例并发 refresh 不能依赖这把锁，只能依赖底层 `TokenStore.Rotate` 的原子性和条件检查
- 如果 store 的 `Rotate` 不是单条原子操作，而是拆成多步写入，就可能出现双成功、旧新 token 同时有效或部分失败后的不一致
- logout 对“已轮换出的后继 token”的级联删除，在多实例下也不是全局可靠的；某个实例不知道另一实例记录的 successor 链时，可能只删除当前 token

**结论**：多实例生产环境中，真正的安全前提是共享存储上的原子 `Rotate`。进程内锁和 successor 链只能降低单实例内的竞争，不能替代分布式锁或存储级原子条件更新。

### 2.6 长期 Token 的风险

Refresh token 本质是长期 bearer secret，风险随时间累积：

- **被动泄露**：token 仍存储在客户端。若使用可被脚本读取的存储介质，XSS 可直接窃取；若使用 `HttpOnly` cookie，XSS 仍可能借助受害者浏览器发起受信请求，但不能直接读出 cookie 值
- **主动攻击**：CSRF 攻击在用户不知情时使用已登录状态发起 refresh 请求
- **服务端存储泄露**：refresh token 是随机 bearer secret，若 token store 被读取，攻击者可直接重放未过期 token

**缓解措施**：

- 设定 refresh token 最大有效期（`RefreshTokenTimeout`），建议不超过 30 天
- 对需要绝对上限的场景，同时设置 `MaxRefresh`，让每次轮换后的实际过期时间不超过 `MaxRefreshUntil`
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

### 3.2 `SendCookie` 与两类 Cookie 的差异

`SendCookie` 只控制“是否把 token 写入响应 cookie”，但它对 access token cookie 和 refresh token cookie 的默认安全属性影响不同：

- `SendCookie: false` 时，不会写 access token cookie，也不会写 refresh token cookie
- `SendCookie: true` 时，`setAccessTokenCookie` 会写入 `CookieName` 指定的 access token cookie，但是否 `Secure` / `HttpOnly` 取决于 middleware 的 `SecureCookie` 和 `CookieHTTPOnly` 配置（需手动设置为 `true`）；同理，直接调用的 `SetCookie` 方法传入的 secure/httpOnly 参数来自 middleware 配置字段，而非由调用方随意指定
- `SendCookie: true` 时，初始化阶段会把 `RefreshTokenSecureCookie` 和 `RefreshTokenCookieHTTPOnly` 自动设为 `true`，然后 `SetRefreshTokenCookie` 再写入 refresh token cookie
- logout 清 cookie 也受 `SendCookie` 控制；如果没有启用 `SendCookie`，logout 不会额外尝试删除浏览器中的 cookie

另外，access token cookie 的 `Max-Age` 以 access token 剩余有效期为准；refresh token cookie 的 `Max-Age` 以 `RefreshExpiresAt` 或 `RefreshTokenTimeout` 为准，二者并不共享同一过期策略。

### 3.3 CookieHTTPOnly

`CookieHTTPOnly: true` 防止 JavaScript 通过 `document.cookie` 读取 Cookie。**必须开启**。

```go
RefreshTokenCookieHTTPOnly: true,  // 启用后 JS 无法访问
```

这是对抗 token 直接泄露的核心防线。即使攻击者能在页面执行 JS，也无法直接读取该 cookie 的值。

注意：当 `SendCookie: true` 时，中间件只会自动加固 refresh token cookie。普通 access token cookie 的 `SecureCookie` 和 `CookieHTTPOnly` 仍需手动显式配置。

### 3.4 CookieSameSite

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

### 3.5 CookieDomain

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
| Refresh Token | 1 天 - 30 天 | 取决于安全需求，更短更安全；若允许持续轮换，建议再设置 `MaxRefresh` 作为绝对上限 |

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
// 当 SendCookie: true 时，RefreshTokenSecureCookie 和 RefreshTokenCookieHTTPOnly 会自动设为 true。
// access token cookie 的 Secure/HttpOnly 不会自动开启，因此仍显式设置 SecureCookie/CookieHTTPOnly。
RefreshTokenSecureCookie: true, // 已自动设置，此处显式声明
RefreshTokenCookieHTTPOnly: true, // 已自动设置，此处显式声明
CookieHTTPOnly: true,
SecureCookie: true, // 生产环境必须为 true
CookieSameSite: http.SameSiteStrictMode,

    // Store 配置
    TokenStore: myProductionTokenStore, // 替换默认内存 store
}
```
