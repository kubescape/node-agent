package signature

type Signer interface {
	Sign(data []byte) (*Signature, error)
}

type Verifier interface {
	Verify(data []byte, sig *Signature) error
}

type SignableProfile interface {
	GetAnnotations() map[string]string
	SetAnnotations(annotations map[string]string)
	GetUID() string
	GetNamespace() string
	GetName() string
	GetContent() interface{}
}

type Signature struct {
	Signature   []byte
	Certificate []byte
	Issuer      string
	Identity    string
	Timestamp   int64
}

type SignOptions struct {
	UseKeyless bool
}

type SignOption func(*SignOptions)

func WithKeyless(useKeyless bool) SignOption {
	return func(opts *SignOptions) {
		opts.UseKeyless = useKeyless
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
