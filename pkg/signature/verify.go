package signature

import (
	"fmt"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func VerifyObject(obj SignableObject, opts ...VerifyOption) error {
	if obj == nil {
		return fmt.Errorf("object is nil")
	}
	options := &VerifyOptions{
		AllowUntrusted: false,
	}

	for _, opt := range opts {
		opt(options)
	}

	annotations := obj.GetAnnotations()
	if annotations == nil {
		return fmt.Errorf("%w (missing %s annotation)", ErrObjectNotSigned, AnnotationSignature)
	}

	if _, ok := annotations[AnnotationSignature]; !ok {
		return fmt.Errorf("%w (missing %s annotation)", ErrObjectNotSigned, AnnotationSignature)
	}

	// useKeyless=true is fine for verification since we use the certificate
	// stored in the object annotations, regardless of how the object was signed
	adapter, err := NewCosignAdapter(true)
	if err != nil {
		return fmt.Errorf("failed to create cosign adapter: %w", err)
	}

	sig, err := adapter.DecodeSignatureFromAnnotations(annotations)
	if err != nil {
		return fmt.Errorf("failed to decode signature from annotations: %w", err)
	}

	content := obj.GetContent()
	hash, err := adapter.GetContentHash(content)
	if err != nil {
		return fmt.Errorf("failed to compute content hash: %w", err)
	}

	verifier, err := NewCosignVerifier(true)
	if err != nil {
		return fmt.Errorf("failed to create verifier: %w", err)
	}

	var verifyErr error
	if options.AllowUntrusted {
		verifyErr = verifier.VerifyAllowUntrusted([]byte(hash), sig)
	} else {
		verifyErr = verifier.Verify([]byte(hash), sig)
	}

	if verifyErr != nil {
		logger.L().Warning("Object signature verification failed",
			helpers.String("namespace", obj.GetNamespace()),
			helpers.String("name", obj.GetName()),
			helpers.String("error", verifyErr.Error()))

		return fmt.Errorf("signature verification failed: %w", verifyErr)
	}

	logger.L().Info("Successfully verified object signature",
		helpers.String("namespace", obj.GetNamespace()),
		helpers.String("name", obj.GetName()),
		helpers.String("identity", sig.Identity),
		helpers.String("issuer", sig.Issuer))

	return nil
}

func VerifyObjectStrict(obj SignableObject) error {
	return VerifyObject(obj, WithUntrusted(false))
}

func VerifyObjectAllowUntrusted(obj SignableObject) error {
	return VerifyObject(obj, WithUntrusted(true))
}
