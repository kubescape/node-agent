package signature

type CosignSigner struct {
	adapter *CosignAdapter
}

func NewCosignSigner(useKeyless bool) (*CosignSigner, error) {
	adapter, err := NewCosignAdapter(useKeyless)
	if err != nil {
		return nil, err
	}

	return &CosignSigner{
		adapter: adapter,
	}, nil
}

func (s *CosignSigner) Sign(data []byte) (*Signature, error) {
	return s.adapter.SignData(data)
}
