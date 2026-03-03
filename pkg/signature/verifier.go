package signature

import "fmt"

type CosignVerifier struct {
	adapter *CosignAdapter
}

func NewCosignVerifier(useKeyless bool) (*CosignVerifier, error) {
	adapter, err := NewCosignAdapter(useKeyless)
	if err != nil {
		return nil, err
	}

	return &CosignVerifier{
		adapter: adapter,
	}, nil
}

func (v *CosignVerifier) Verify(data []byte, sig *Signature) error {
	if v == nil || v.adapter == nil {
		return fmt.Errorf("verifier not initialized")
	}
	if sig == nil {
		return fmt.Errorf("signature is nil")
	}
	return v.adapter.VerifyData(data, sig, false)
}

func (v *CosignVerifier) VerifyAllowUntrusted(data []byte, sig *Signature) error {
	if v == nil || v.adapter == nil {
		return fmt.Errorf("verifier not initialized")
	}
	if sig == nil {
		return fmt.Errorf("signature is nil")
	}
	return v.adapter.VerifyData(data, sig, true)
}
