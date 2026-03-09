package signature

import (
	"fmt"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func SignProfile(profile SignableProfile, opts ...SignOption) error {
	if profile == nil {
		return fmt.Errorf("profile is nil")
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

	content := profile.GetContent()

	hash, err := adapter.GetContentHash(content)
	if err != nil {
		return fmt.Errorf("failed to compute content hash: %w", err)
	}

	logger.L().Debug("Signing profile",
		helpers.String("namespace", profile.GetNamespace()),
		helpers.String("name", profile.GetName()),
		helpers.String("contentHash", hash))

	sig, err := adapter.SignData([]byte(hash))
	if err != nil {
		return fmt.Errorf("failed to sign profile: %w", err)
	}

	annotations, err := adapter.EncodeSignatureToAnnotations(sig)
	if err != nil {
		return fmt.Errorf("failed to encode signature to annotations: %w", err)
	}

	existingAnnotations := profile.GetAnnotations()
	if existingAnnotations == nil {
		existingAnnotations = make(map[string]string)
	}

	for k, v := range annotations {
		existingAnnotations[k] = v
	}

	profile.SetAnnotations(existingAnnotations)

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

	adapter := &CosignAdapter{}
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
