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
| Refresh Token 存储 | 默认内存存储，支持实现 `TokenStore` 替换 |

## 快速开始

```go
privateKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
if err != nil {
    panic(err)
}

mw := &jwtmw.ToukaJWTMiddleware{
    Realm:  "test zone",
    Key:    privateKey,
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