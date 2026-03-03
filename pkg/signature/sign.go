package signature

import (
	"encoding/json"
	"fmt"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func SignProfile(profile SignableProfile, opts ...SignOption) error {
	options := &SignOptions{
		UseKeyless: true,
	}

	for _, opt := range opts {
		opt(options)
	}

	signer, err := NewCosignSigner(options.UseKeyless)
	if err != nil {
		return fmt.Errorf("failed to create signer: %w", err)
	}

	content := profile.GetContent()

	contentBytes, err := json.Marshal(content)
	if err != nil {
		return fmt.Errorf("failed to marshal profile content: %w", err)
	}

	adapter, err := NewCosignAdapter(options.UseKeyless)
	if err != nil {
		return fmt.Errorf("failed to create cosign adapter: %w", err)
	}

	hash, err := adapter.GetContentHash(content)
	if err != nil {
		return fmt.Errorf("failed to compute content hash: %w", err)
	}

	logger.L().Debug("Signing profile",
		helpers.String("namespace", profile.GetNamespace()),
		helpers.String("name", profile.GetName()),
		helpers.String("contentHash", hash))

	sig, err := signer.Sign(contentBytes)
	if err != nil {
		return fmt.Errorf("failed to sign profile: %w", err)
	}

	annotations, err := adapter.EncodeSignatureToAnnotations(sig)
	if err != nil {
		return fmt.Errorf("failed to encode signature to annotations: %w", err)
	}

	profile.SetAnnotations(annotations)

	logger.L().Info("Successfully signed profile",
		helpers.String("namespace", profile.GetNamespace()),
		helpers.String("name", profile.GetName()),
		helpers.String("identity", sig.Identity),
		helpers.String("issuer", sig.Issuer))

	return nil
}

func SignProfileWithKey(profile SignableProfile) error {
	return SignProfile(profile, WithKeyless(false))
}

func SignProfileKeyless(profile SignableProfile) error {
	return SignProfile(profile, WithKeyless(true))
}

func GetProfileSignature(profile SignableProfile) (*Signature, error) {
	annotations := profile.GetAnnotations()
	if annotations == nil {
		return nil, fmt.Errorf("profile has no annotations")
	}

	adapter, err := NewCosignAdapter(true)
	if err != nil {
		return nil, fmt.Errorf("failed to create cosign adapter: %w", err)
	}

	sig, err := adapter.DecodeSignatureFromAnnotations(annotations)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature from annotations: %w", err)
	}

	return sig, nil
}

func IsSigned(profile SignableProfile) bool {
	annotations := profile.GetAnnotations()
	if annotations == nil {
		return false
	}

	_, ok := annotations[AnnotationSignature]
	return ok
}
