//go:build experimental_signing

package signature

import (
	"encoding/json"
	"fmt"
	"maps"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	apivalidation "k8s.io/apimachinery/pkg/api/validation"
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

	content := obj.GetContent()

	// With EmbedContent the exact signed bytes ride along in an annotation, so
	// the signature stays verifiable regardless of server-side normalisation.
	var contentBytes []byte
	if options.EmbedContent {
		var err error
		contentBytes, err = json.Marshal(content)
		if err != nil {
			return fmt.Errorf("failed to marshal content for embedding: %w", err)
		}
		// Match the verifier's decompressed limit before constructing a signer
		// or changing annotations, so signing cannot produce an unusable artifact.
		if len(contentBytes) > maxEmbeddedContentBytes {
			return fmt.Errorf("embedded content exceeds %d bytes", maxEmbeddedContentBytes)
		}
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

	if options.EmbedContent {
		enc, err := encodeEmbeddedContent(contentBytes)
		if err != nil {
			return fmt.Errorf("failed to encode embedded content: %w", err)
		}
		annotations[AnnotationContent] = enc
	}

	if err := publishSignedAnnotations(obj, annotations); err != nil {
		return err
	}

	logger.L().Info("Successfully signed object",
		helpers.String("namespace", obj.GetNamespace()),
		helpers.String("name", obj.GetName()),
		helpers.String("identity", sig.Identity),
		helpers.String("issuer", sig.Issuer))

	return nil
}

// Publish only after the complete annotation set passes resource size limits.
func publishSignedAnnotations(obj SignableObject, signed map[string]string) error {
	annotations := maps.Clone(obj.GetAnnotations())
	if annotations == nil {
		annotations = make(map[string]string)
	}
	// Re-signing without embedding must remove a previously embedded payload.
	delete(annotations, AnnotationContent)
	maps.Copy(annotations, signed)
	if _, resource := obj.(ResourceSignableObject); resource {
		if err := apivalidation.ValidateAnnotationsSize(annotations); err != nil {
			return fmt.Errorf("signed object exceeds Kubernetes annotation limit: %w; reduce embedded content or existing annotations", err)
		}
	}
	obj.SetAnnotations(annotations)
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
