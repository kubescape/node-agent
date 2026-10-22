//go:build experimental_signing

package signature

import (
	"fmt"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/storage/pkg/utils"
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

	// When the canonical signed content is embedded (vendor-shipped artifacts),
	// verify against THOSE bytes: the server normalises specs on save, so the
	// object's own content may legitimately differ from what was signed. The
	// embedded bytes are then the verified source of truth for consumers.
	var hash string
	if embedded, present, embErr := EmbeddedContent(obj); present {
		// A malformed embedded blob on an object that CLAIMS to be signed is a
		// tamper signal, not an operational hiccup — wrap with
		// ErrSignatureMismatch so the caller raises R1016 and fails closed
		// rather than swallowing it as "operational" and (in permissive mode)
		// loading the object anyway.
		if embErr != nil {
			return fmt.Errorf("%w: malformed embedded content: %v", ErrSignatureMismatch, embErr)
		}
		// Bind the embedded content to THIS carrier: the signed bytes must
		// commit to the same name+namespace, else a validly-signed blob could be
		// stapled onto a different object (whose live spec would then be used).
		if bindErr := checkEmbeddedBinding(obj, embedded); bindErr != nil {
			return fmt.Errorf("%w: %v", ErrSignatureMismatch, bindErr)
		}
		hash, embErr = utils.CanonicalHash(embedded)
		if embErr != nil {
			return fmt.Errorf("%w: cannot hash embedded content: %v", ErrSignatureMismatch, embErr)
		}
	} else {
		content := obj.GetContent()
		var err error
		hash, err = adapter.GetContentHash(content)
		if err != nil {
			return fmt.Errorf("failed to compute content hash: %w", err)
		}
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

		// Wrap with the ErrSignatureMismatch sentinel so callers can
		// distinguish actual tamper from operational errors (hash
		// computation, verifier construction) returned above.
		// errors.Is(err, ErrSignatureMismatch) is the canonical check.
		return fmt.Errorf("%w: %w", ErrSignatureMismatch, verifyErr)
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
