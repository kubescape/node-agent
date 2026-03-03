package signature

const (
	AnnotationPrefix = "signature.kubescape.io"

	AnnotationSignature   = AnnotationPrefix + "/signature"
	AnnotationCertificate = AnnotationPrefix + "/certificate"
	AnnotationIssuer      = AnnotationPrefix + "/issuer"
	AnnotationIdentity    = AnnotationPrefix + "/identity"
	AnnotationTimestamp   = AnnotationPrefix + "/timestamp"
)
