package signature

import "errors"

const (
	AnnotationPrefix = "signature.kubescape.io"

	AnnotationSignature   = AnnotationPrefix + "/signature"
	AnnotationCertificate = AnnotationPrefix + "/certificate"
	AnnotationRekorBundle = AnnotationPrefix + "/rekor-bundle"
	AnnotationIssuer      = AnnotationPrefix + "/issuer"
	AnnotationIdentity    = AnnotationPrefix + "/identity"
	AnnotationTimestamp   = AnnotationPrefix + "/timestamp"
)

var ErrObjectNotSigned = errors.New("object is not signed (missing signature annotation)")

// ErrSignatureMismatch wraps the underlying cosign verifier failure when a
// signature is present but does not verify against the object's content +
// certificate. Callers (e.g. ContainerProfileCache's tamper-alert path)
// MUST distinguish this from operational errors (hash computation failure,
// verifier construction failure, malformed signature annotations) — only
// ErrSignatureMismatch indicates an actual tamper event.
var ErrSignatureMismatch = errors.New("signature verification failed")
