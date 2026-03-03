package signature

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
	return v.adapter.VerifyData(data, sig, false)
}

func (v *CosignVerifier) VerifyAllowUntrusted(data []byte, sig *Signature) error {
	return v.adapter.VerifyData(data, sig, true)
}
