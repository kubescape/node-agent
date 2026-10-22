//go:build experimental_signing

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

	// AnnotationContent carries the exact canonical content the signature was
	// computed over (base64(gzip(JSON))). Storage normalises object SPECS on
	// save (deflate — cluster-configurable, so not reproducible offline) but
	// never touches annotations; embedding the signed content makes the
	// signature chain independent of any server-side conversion: verification
	// binds to these bytes, and consumers use them as the verified source of
	// truth.
	AnnotationContent = AnnotationPrefix + "/content"
)

var ErrObjectNotSigned = errors.New("object is not signed (missing signature annotation)")

// ErrSignatureMismatch reports invalid signature material, including malformed
// annotations, or a signature that does not verify against the object's content
// and certificate. Callers distinguish this from verification machinery errors
// such as hash computation or verifier construction failures.
var ErrSignatureMismatch = errors.New("signature verification failed")
