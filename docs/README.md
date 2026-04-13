# Touka JWT Middleware

Touka 框架的 JWT 中间件，移植自 [appleboy/gin-jwt](https://github.com/appleboy/gin-jwt)。

内置并默认使用 `ML-DSA-65` 签名算法，支持通过 `Algorithm` 接口扩展其他算法。

## 文档目录

- [配置参考](./configuration.md) - 所有配置项说明
- [API 文档](./api.md) - Handler 和方法说明
- [安全最佳实践](./security.md) - 生产环境安全建议
- [使用示例](./examples.md) - 完整集成示例

## 核心特性

| 特性 | 说明 |
|------|------|
| 默认算法 | ML-DSA-65 |
| Token 提取 | header / query / cookie / param / form |
| Refresh Token | 仅从 cookie 或 form body 提取，避免暴露在 URL |
| Refresh Token 存储 | 默认内存存储 (`InMemoryRefreshTokenStore`)，支持实现 `TokenStore` 替换 |
| Token 轮换 | `RefreshHandler` 要求 store 实现 `RefreshTokenRotator`；默认内存 store 已提供原子轮换 |

## 默认值

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| Timeout | 1小时 | Access Token 过期时间 |
| MaxRefresh | 7天 | Refresh Token 最大过期时间 |
| TokenLookup | header:Authorization | Token 提取位置 |
| IdentityKey | identity | Payload 中身份标识字段名 |
| TokenHeadName | Bearer | Token 前缀名称 |
| SigningAlgorithm | ML-DSA-65 | 签名算法 |
| ExpField | exp | Token 过期时间字段名 |
| CookieName | jwt | Access Token Cookie 名称 |
| RefreshTokenCookieName | refresh_token | Refresh Token Cookie 名称 |

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
