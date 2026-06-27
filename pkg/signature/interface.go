package signature

import (
	"crypto/ecdsa"
)

type Signer interface {
	Sign(data []byte) (*Signature, error)
}

type Verifier interface {
	Verify(data []byte, sig *Signature) error
}

type SignableObject interface {
	GetAnnotations() map[string]string
	SetAnnotations(annotations map[string]string)
	GetUID() string
	GetNamespace() string
	GetName() string
	GetContent() interface{}
	GetUpdatedObject() interface{}
}

type Signature struct {
	Signature   []byte
	Certificate []byte
	RekorBundle []byte
	Issuer      string
	Identity    string
	Timestamp   int64
}

type SignOptions struct {
	UseKeyless bool
	PrivateKey *ecdsa.PrivateKey
}

type SignOption func(*SignOptions)

func WithKeyless(useKeyless bool) SignOption {
	return func(opts *SignOptions) {
		opts.UseKeyless = useKeyless
	}
}

func WithPrivateKey(privateKey *ecdsa.PrivateKey) SignOption {
	return func(opts *SignOptions) {
		opts.PrivateKey = privateKey
	}
}

type VerifyOptions struct {
	AllowUntrusted bool
}

type VerifyOption func(*VerifyOptions)

func WithUntrusted(allowUntrusted bool) VerifyOption {
	return func(opts *VerifyOptions) {
		opts.AllowUntrusted = allowUntrusted
	}
}
