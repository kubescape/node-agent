package signature

import (
	"encoding/json"
	"fmt"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func VerifyProfile(profile SignableProfile, opts ...VerifyOption) error {
	if profile == nil {
		return fmt.Errorf("profile is nil")
	}
	options := &VerifyOptions{
		AllowUntrusted: false,
	}

	for _, opt := range opts {
		opt(options)
	}

	annotations := profile.GetAnnotations()
	if annotations == nil {
		return fmt.Errorf("profile has no annotations")
	}

	if _, ok := annotations[AnnotationSignature]; !ok {
		return fmt.Errorf("profile is not signed (missing %s annotation)", AnnotationSignature)
	}

	// useKeyless=true is fine for verification since we use the certificate
	// stored in the profile annotations, regardless of how the profile was signed
	adapter, err := NewCosignAdapter(true)
	if err != nil {
		return fmt.Errorf("failed to create cosign adapter: %w", err)
	}

	sig, err := adapter.DecodeSignatureFromAnnotations(annotations)
	if err != nil {
		return fmt.Errorf("failed to decode signature from annotations: %w", err)
	}

	content := profile.GetContent()

	contentBytes, err := json.Marshal(content)
	if err != nil {
		return fmt.Errorf("failed to marshal profile content: %w", err)
	}

	verifier, err := NewCosignVerifier(true)
	if err != nil {
		return fmt.Errorf("failed to create verifier: %w", err)
	}

	var verifyErr error
	if options.AllowUntrusted {
		verifyErr = verifier.VerifyAllowUntrusted(contentBytes, sig)
	} else {
		verifyErr = verifier.Verify(contentBytes, sig)
	}

	if verifyErr != nil {
		logger.L().Warning("Profile signature verification failed",
			helpers.String("namespace", profile.GetNamespace()),
			helpers.String("name", profile.GetName()),
			helpers.String("error", verifyErr.Error()))

		return fmt.Errorf("signature verification failed: %w", verifyErr)
	}

	logger.L().Info("Successfully verified profile signature",
		helpers.String("namespace", profile.GetNamespace()),
		helpers.String("name", profile.GetName()),
		helpers.String("identity", sig.Identity),
		helpers.String("issuer", sig.Issuer))

	return nil
}

func VerifyProfileStrict(profile SignableProfile) error {
	return VerifyProfile(profile, WithUntrusted(false))
}

func VerifyProfileAllowUntrusted(profile SignableProfile) error {
	return VerifyProfile(profile, WithUntrusted(true))
}
