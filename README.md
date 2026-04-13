# Touka JWT Middleware

本项目移植自 [appleboy/gin-jwt](https://github.com/appleboy/gin-jwt)，原始许可证见 [LICENSE-GIN](LICENSE-GIN)。

Touka 的 JWT 中间件。

当前默认使用 `ML-DSA-65`，同时把算法接入抽象成接口。包内已注册 `ML-DSA-65` 与 `HS512` 两个实现，也支持继续注册其他签名算法实现。

## Current Defaults

- 默认 `SigningAlgorithm`：`ML-DSA-65`
- 包内已注册算法实现：`ML-DSA-65`、`HS512`
- refresh token 默认存储：内存 `TokenStore`
- refresh token 提取顺序：cookie，然后 form
- 示例 refresh endpoint：`POST /refresh_token`
- `TokenLookup`：`header:Authorization`
- `Timeout`：`time.Hour`
- `RefreshTokenTimeout`：若 `MaxRefresh != 0` 则默认等于 `MaxRefresh`，否则默认 `7 * 24 * time.Hour`
- `TimeFunc`：`time.Now`
- `IdentityKey`：`identity`
- `TokenHeadName`：`Bearer`
- `ExpField`：`exp`
- `CookieName`：`jwt`
- `RefreshTokenCookieName`：`refresh_token`

## Breaking Changes

如果你从旧版本迁移，需要注意：

- 如果继续使用默认算法 `ML-DSA-65`，旧的 `HS*` / `RS*` token 不会直接通过验签
- 如果继续使用默认算法 `ML-DSA-65`，旧的 `Key: []byte("secret")` 初始化方式不再适用
- 在 `ML-DSA-65` 下，`PrivKeyBytes` / `PrivKeyFile` 不再表示 HMAC secret 或 PEM，它们现在是算法实现自己的 key 输入字节
- 默认内置算法 `ML-DSA-65` 下：
  - `PrivKeyBytes` / `PrivKeyFile` 表示原始 32 字节 seed
  - `PubKeyBytes` / `PubKeyFile` 表示 `mldsa.PublicKey.Bytes()` 的原始编码

这意味着升级时需要重新登录或做一次 token 切换，因为旧 access token 不能被新中间件继续接受。

## Install

```sh
go get github.com/fenthope/jwt
```

## Basic Usage

```go
package main

import (
	"time"

	"filippo.io/mldsa"
	jwtmw "github.com/fenthope/jwt"
	"github.com/infinite-iroha/touka"
)

func middleware() *jwtmw.ToukaJWTMiddleware {
	privateKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		panic(err)
	}

	mw, err := jwtmw.New(&jwtmw.ToukaJWTMiddleware{
		Realm:      "test zone",
		Key:        privateKey,
		Timeout:    time.Hour,
		MaxRefresh: 7 * 24 * time.Hour,
		Authenticator: func(c *touka.Context) (any, error) {
			return "admin", nil
		},
		PayloadFunc: func(data any) jwtmw.MapClaims {
			return jwtmw.MapClaims{"identity": data}
		},
	})
	if err != nil {
		panic(err)
	}

	return mw
}
```

## Verify-Only Mode

如果某个服务只需要验签、不需要签发 token，可以只提供公钥输入：

```go
mw, err := jwtmw.New(&jwtmw.ToukaJWTMiddleware{
	Realm: "test zone",
	PubKeyBytes: publicKey.Bytes(),
	SigningAlgorithm: jwtmw.SigningAlgorithmMLDSA65,
})
if err != nil {
	panic(err)
}
```

这种模式下：

- `ParseToken` / `MiddlewareFunc` 可正常工作
- `LoginHandler` / `RefreshHandler` 内部签发 access token 时会因为缺少私钥而失败

## Algorithm Abstraction

算法通过 `Algorithm` 接口接入：

```go
type Algorithm interface {
	Alg() string
	SigningMethod() jwt.SigningMethod
	LoadSigningKey(seedOrKey []byte) (any, error)
	LoadVerificationKey(encoded []byte) (any, error)
	VerificationKeyFromSigningKey(signingKey any) (any, error)
}
```

可以通过 `RegisterAlgorithm` 注册新的实现。

如果 `SigningAlgorithm` 留空，仍默认选择内置的 `ML-DSA-65`。

包内还注册了一个 `HS512` 适配实现，主要用于验证 `Algorithm` 接口可以接入其他算法。它更适合作为兼容性样例，不代表这里推荐把 `HS512` 作为默认生产配置。

## Built-In ML-DSA-65 Semantics

默认内置算法 `ML-DSA-65` 的字段含义：

- `Key`: `*mldsa.PrivateKey`
- `PrivKeyBytes`: 原始 32 字节 seed
- `PrivKeyFile`: 文件内容必须是原始 32 字节 seed
- `PubKeyBytes`: `mldsa.PublicKey.Bytes()` 的结果
- `PubKeyFile`: 文件内容必须是 `mldsa.PublicKey.Bytes()` 的结果

注意：这些都不是 PEM，也不是 PKCS#8。

## Safer Refresh Flow

refresh token 是长期 bearer secret，不应该放在 URL 里。

当前实现只从以下位置读取 refresh token：

- cookie
- form body

推荐使用 `POST` + cookie 或 `POST` + form，不要把 refresh token 放到 query string。

`RefreshHandler` 要求 `TokenStore` 实现原子 refresh rotation。为此，store 必须实现 `core.RefreshTokenRotator`：

```go
type RefreshTokenRotator interface {
	TokenStore
	Rotate(ctx context.Context, oldToken, newToken string, userData any, expiry time.Time) error
}
```

如果 store 没有实现这个接口，`RefreshHandler` 会返回错误而不是回退到非原子 `Set(new) -> Delete(old)` 流程。默认内存 store 已实现该接口。

refresh token 的生命周期还受两个时长共同影响：

- 每次生成或轮换时，底层 store 中保存的 refresh token 过期时间为 `min(now + RefreshTokenTimeout, MaxRefreshUntil)`
- 如果设置了 `MaxRefresh`，首次登录时会把绝对上限写入 `RefreshTokenState.MaxRefreshUntil`
- `RefreshHandler` 返回的新 refresh token 会继承原来的绝对上限，不会因为轮换而无限续期

## Example App

完整示例见 `_example/basic/server.go`。

示例为了便于本地运行，会在启动时生成临时 `ML-DSA-65` 私钥。这个行为只适合演示，不适合生产环境。

生产环境应当：

- 持久化 signing key
- 在多个实例间共享同一套 signing / verification key
- 替换默认内存 refresh token store

## Example Routes

- `POST /login`
- `POST /refresh_token`
- `GET /auth/hello`

## Notes

- `TokenLookup` 仍支持 access token 从 `header` / `query` / `cookie` / `param` / `form` 读取
- refresh token 提取不使用 `TokenLookup`，而是固定走 `RefreshTokenCookieName` 对应的 cookie 和同名 form 字段
- 默认认证头前缀仍是 `Bearer`
