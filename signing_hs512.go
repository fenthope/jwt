package jwt

import (
	"errors"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

const SigningAlgorithmHS512 = "HS512"

type hs512Algorithm struct{}

func init() {
	RegisterAlgorithm(hs512Algorithm{})
}

func (hs512Algorithm) Alg() string {
	return SigningAlgorithmHS512
}

func (hs512Algorithm) SigningMethod() jwtlib.SigningMethod {
	return jwtlib.SigningMethodHS512
}

func (hs512Algorithm) LoadSigningKey(seedOrKey []byte) (any, error) {
	if len(seedOrKey) == 0 {
		return nil, errors.Join(jwtlib.ErrInvalidKeyType, errors.New("HS512 requires a non-empty key"))
	}
	return seedOrKey, nil
}

func (hs512Algorithm) LoadVerificationKey(encoded []byte) (any, error) {
	if len(encoded) == 0 {
		return nil, errors.Join(jwtlib.ErrInvalidKeyType, errors.New("HS512 requires a non-empty verification key"))
	}
	return encoded, nil
}

func (hs512Algorithm) VerificationKeyFromSigningKey(signingKey any) (any, error) {
	k, ok := signingKey.([]byte)
	if !ok {
		return nil, errors.Join(jwtlib.ErrInvalidKeyType, errors.New("expected []byte for HS512 signing key"))
	}
	return k, nil
}
