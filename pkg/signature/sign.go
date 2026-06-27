package signature

import (
	"fmt"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func SignObject(obj SignableObject, opts ...SignOption) error {
	if obj == nil {
		return fmt.Errorf("object is nil")
	}
	options := &SignOptions{
		UseKeyless: true,
	}

	for _, opt := range opts {
		opt(options)
	}

	var adapter *CosignAdapter
	var err error

	if options.PrivateKey != nil {
		adapter, err = NewCosignAdapterWithPrivateKey(false, options.PrivateKey)
	} else {
		adapter, err = NewCosignAdapter(options.UseKeyless)
	}

	if err != nil {
		return fmt.Errorf("failed to create cosign adapter: %w", err)
	}

	content := obj.GetContent()

	hash, err := adapter.GetContentHash(content)
	if err != nil {
		return fmt.Errorf("failed to compute content hash: %w", err)
	}

	logger.L().Debug("Signing object",
		helpers.String("namespace", obj.GetNamespace()),
		helpers.String("name", obj.GetName()),
		helpers.String("contentHash", hash))

	sig, err := adapter.SignData([]byte(hash))
	if err != nil {
		return fmt.Errorf("failed to sign object: %w", err)
	}

	annotations, err := adapter.EncodeSignatureToAnnotations(sig)
	if err != nil {
		return fmt.Errorf("failed to encode signature to annotations: %w", err)
	}

	existingAnnotations := obj.GetAnnotations()
	if existingAnnotations == nil {
		existingAnnotations = make(map[string]string)
	}

	for k, v := range annotations {
		existingAnnotations[k] = v
	}

	obj.SetAnnotations(existingAnnotations)

	logger.L().Info("Successfully signed object",
		helpers.String("namespace", obj.GetNamespace()),
		helpers.String("name", obj.GetName()),
		helpers.String("identity", sig.Identity),
		helpers.String("issuer", sig.Issuer))

	return nil
}

func SignObjectDisableKeyless(obj SignableObject) error {
	return SignObject(obj, WithKeyless(false))
}

func SignObjectKeyless(obj SignableObject) error {
	return SignObject(obj, WithKeyless(true))
}

func GetObjectSignature(obj SignableObject) (*Signature, error) {
	if obj == nil {
		return nil, fmt.Errorf("GetObjectSignature: nil object")
	}
	annotations := obj.GetAnnotations()
	if annotations == nil {
		return nil, fmt.Errorf("object has no annotations")
	}

	adapter := &CosignAdapter{}
	sig, err := adapter.DecodeSignatureFromAnnotations(annotations)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature from annotations: %w", err)
	}

	return sig, nil
}

func IsSigned(obj SignableObject) bool {
	if obj == nil {
		return false
	}
	annotations := obj.GetAnnotations()
	if annotations == nil {
		return false
	}

	_, ok := annotations[AnnotationSignature]
	return ok
}
