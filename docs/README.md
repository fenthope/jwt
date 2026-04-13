# Touka JWT Middleware

Touka 框架的 JWT 中间件，移植自 [appleboy/gin-jwt](https://github.com/appleboy/gin-jwt)。

内置并默认使用 `ML-DSA-65` 签名算法，支持通过 `Algorithm` 接口注册和扩展其他算法。

## 文档目录

- [配置参考](./configuration.md) - 所有配置项说明
- [API 文档](./api.md) - Handler 和方法说明
- [安全最佳实践](./security.md) - 生产环境安全建议
- [使用示例](./examples.md) - 完整集成示例

## 核心特性

| 特性 | 说明 |
|------|------|
| 默认算法 | ML-DSA-65 |
| Access Token 提取 | 支持 `header / query / cookie / param / form`，默认仅 `header:Authorization`，可通过逗号组合多个来源 |
| Refresh Token | 仅从 cookie 或 form body 提取，避免暴露在 URL |
| Refresh Token 存储 | 默认使用内存存储 `InMemoryRefreshTokenStore`；可替换为自定义 `TokenStore` |
| Refresh Token 状态 | 配置 `MaxRefresh` 时，store 中保存 `RefreshTokenState{user_data, max_refresh_until}`；未配置时直接保存用户数据 |
| Token 轮换 | `RefreshHandler` 会生成新的 refresh token，并要求 store 实现 `RefreshTokenRotator` 做原子轮换；默认内存 store 已实现 |
| Logout 行为 | `LogoutHandler` 会删除当前 refresh token；若该 token 已在本进程内被轮换，还会继续删除已记录的后继 token 链 |

## 默认值

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| Timeout | 1小时 | Access Token 过期时间 |
| MaxRefresh | 0（未启用） | Refresh Token 绝对续期上限；为 0 时不设置 `max_refresh_until` |
| RefreshTokenTimeout | 7天 | Refresh Token 单次存储 TTL；若显式设置 `MaxRefresh` 且未设置该项，则继承 `MaxRefresh` |
| TokenLookup | header:Authorization | Token 提取位置 |
| IdentityKey | identity | Payload 中身份标识字段名 |
| TokenHeadName | Bearer | Token 前缀名称 |
| SigningAlgorithm | ML-DSA-65 | 签名算法 |
| ExpField | exp | Token 过期时间字段名 |
| CookieName | jwt | Access Token Cookie 名称 |
| RefreshTokenCookieName | refresh_token | Refresh Token Cookie/Form 名称（可配置）；默认从同名的 cookie 或 form 字段提取 |
| `SendCookie` | `false` | 是否将 token 写入 cookie |
| `SecureCookie` | `false` | Access Token Cookie 的 Secure 属性；需手动设置为 `true` 才生效，`SendCookie=true` 不会自动覆盖 |
| `CookieHTTPOnly` | `false` | Access Token Cookie 的 HttpOnly 属性；需手动设置为 `true` 才生效，`SendCookie=true` 不会自动覆盖 |
| `RefreshTokenSecureCookie` | `false`，但当 `SendCookie=true` 时强制设为 `true` | Refresh Token Cookie 的 Secure 属性 |
| `RefreshTokenCookieHTTPOnly | `false`，但当 `SendCookie=true` 时强制设为 `true` | Refresh Token Cookie 的 HttpOnly 属性 |

## Refresh Token 行为摘要

- 登录时会同时生成 access token 和 refresh token，并将 refresh token 写入 `TokenStore`。
- `RefreshHandler` 只接受两种 refresh token 来源：`RefreshTokenCookieName` 对应的 cookie 或同名 form 字段（默认名为 `refresh_token`）。
- 刷新时会保留原有 refresh token 的绝对过期上限：新的 token 过期时间取 `now + RefreshTokenTimeout` 与 `max_refresh_until` 中较早者。
- 如果 `TokenStore` 没有实现 `RefreshTokenRotator`，刷新会直接失败并返回错误，而不是退化为非原子删除加写入。
- 默认内存 store 会在 `Get` 时按需删除当前已过期 token，在 `Cleanup` 时批量清理过期 token；`Rotate` 只针对参与轮换的旧 token 做过期检查，并保证单个 token 的轮换是原子的。

## 快速开始

```go
seed := make([]byte, mldsa.MLDSA65().SeedSize())
if _, err := io.ReadFull(rand.Reader, seed); err != nil {
    panic(err)
}

mw := &jwtmw.ToukaJWTMiddleware{
    Realm: "test zone",
    PrivKeyBytes: seed,
    Timeout: time.Hour,
    MaxRefresh: 7 * 24 * time.Hour,
    Authenticator: func(c *touka.Context) (any, error) {
        return "admin", nil
    },
    PayloadFunc: func(data any) jwtmw.MapClaims {
        return jwtmw.MapClaims{"identity": data}
    },
}
```

完整示例见 [_example/basic/server.go](../_example/basic/server.go)。
