package jwt

import (
	"errors"
	"sync"

	"filippo.io/mldsa"
	jwtlib "github.com/golang-jwt/jwt/v5"
)

// SigningAlgorithmMLDSA65 is the built-in default JWT alg for this package.
const SigningAlgorithmMLDSA65 = "ML-DSA-65"

// Algorithm defines how this package loads keys and binds them to jwt/v5.
// Implementations can register additional algorithms while ML-DSA-65 remains
// built-in and the default when SigningAlgorithm is empty.
type Algorithm interface {
	Alg() string
	SigningMethod() jwtlib.SigningMethod
	LoadSigningKey(seedOrKey []byte) (any, error)
	LoadVerificationKey(encoded []byte) (any, error)
	VerificationKeyFromSigningKey(signingKey any) (any, error)
}

type signingMethodMLDSA65 struct{}

type mldsa65Algorithm struct{}

var (
	SigningMethodMLDSA65 jwtlib.SigningMethod = &signingMethodMLDSA65{}

	algorithmsMu sync.RWMutex
	algorithms   = map[string]Algorithm{}
)

func init() {
	jwtlib.RegisterSigningMethod(SigningAlgorithmMLDSA65, func() jwtlib.SigningMethod {
		return SigningMethodMLDSA65
	})
	RegisterAlgorithm(mldsa65Algorithm{})
}

func RegisterAlgorithm(alg Algorithm) {
	algorithmsMu.Lock()
	defer algorithmsMu.Unlock()
	algorithms[alg.Alg()] = alg
}

func LookupAlgorithm(name string) (Algorithm, bool) {
	algorithmsMu.RLock()
	defer algorithmsMu.RUnlock()
	alg, ok := algorithms[name]
	return alg, ok
}

func (m *signingMethodMLDSA65) Alg() string {
	return SigningAlgorithmMLDSA65
}

func (m *signingMethodMLDSA65) Sign(signingString string, key any) ([]byte, error) {
	switch k := key.(type) {
	case *mldsa.PrivateKey:
		return k.Sign(nil, []byte(signingString), nil)
	default:
		return nil, errors.Join(jwtlib.ErrInvalidKeyType, errors.New("expected *mldsa.PrivateKey"))
	}
}

func (m *signingMethodMLDSA65) Verify(signingString string, sig []byte, key any) error {
	switch k := key.(type) {
	case *mldsa.PublicKey:
		return mldsa.Verify(k, []byte(signingString), sig, nil)
	case *mldsa.PrivateKey:
		return mldsa.Verify(k.PublicKey(), []byte(signingString), sig, nil)
	default:
		return errors.Join(jwtlib.ErrInvalidKeyType, errors.New("expected *mldsa.PublicKey or *mldsa.PrivateKey"))
	}
}

func (mldsa65Algorithm) Alg() string {
	return SigningAlgorithmMLDSA65
}

func (mldsa65Algorithm) SigningMethod() jwtlib.SigningMethod {
	return SigningMethodMLDSA65
}

func (mldsa65Algorithm) LoadSigningKey(seedOrKey []byte) (any, error) {
	return mldsa.NewPrivateKey(mldsa.MLDSA65(), seedOrKey)
}

func (mldsa65Algorithm) LoadVerificationKey(encoded []byte) (any, error) {
	return mldsa.NewPublicKey(mldsa.MLDSA65(), encoded)
}

func (mldsa65Algorithm) VerificationKeyFromSigningKey(signingKey any) (any, error) {
	key, ok := signingKey.(*mldsa.PrivateKey)
	if !ok {
		return nil, errors.Join(jwtlib.ErrInvalidKeyType, errors.New("expected *mldsa.PrivateKey"))
	}
	return key.PublicKey(), nil
}
