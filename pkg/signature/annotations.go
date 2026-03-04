package signature

const (
	AnnotationPrefix = "signature.kubescape.io"

	AnnotationSignature   = AnnotationPrefix + "/signature"
	AnnotationCertificate = AnnotationPrefix + "/certificate"
	AnnotationRekorBundle = AnnotationPrefix + "/rekor-bundle"
	AnnotationIssuer      = AnnotationPrefix + "/issuer"
	AnnotationIdentity    = AnnotationPrefix + "/identity"
	AnnotationTimestamp   = AnnotationPrefix + "/timestamp"
)
