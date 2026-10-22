//go:build experimental_signing

package signature

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
)

// maxEmbeddedContentBytes bounds the decompressed size of the embedded content
// annotation. A ContainerProfile spec is well under this; the cap defends
// against a gzip bomb in the attacker-controlled annotation (etcd allows ~256KB
// of annotation, which gzip can expand ~1000x) driving node-agent OOM, since
// verification runs on every cache load and reconcile tick.
const maxEmbeddedContentBytes = 8 << 20 // 8 MiB

// encodeEmbeddedContent packs canonical content bytes for the
// AnnotationContent annotation: base64(gzip(bytes)).
func encodeEmbeddedContent(content []byte) (string, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(content); err != nil {
		return "", fmt.Errorf("gzip embedded content: %w", err)
	}
	if err := zw.Close(); err != nil {
		return "", fmt.Errorf("gzip close: %w", err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// decodeEmbeddedContent unpacks an AnnotationContent value, bounded to
// maxEmbeddedContentBytes to prevent a decompression bomb.
func decodeEmbeddedContent(encoded string) ([]byte, error) {
	gz, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64-decode embedded content: %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, fmt.Errorf("gunzip embedded content: %w", err)
	}
	defer zr.Close()
	// Read one extra byte so an over-limit payload is detected rather than
	// silently truncated (a truncation would change the hash → tamper anyway,
	// but an explicit error is clearer and cheaper).
	out, err := io.ReadAll(io.LimitReader(zr, maxEmbeddedContentBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read embedded content: %w", err)
	}
	if len(out) > maxEmbeddedContentBytes {
		return nil, fmt.Errorf("embedded content exceeds %d bytes", maxEmbeddedContentBytes)
	}
	return out, nil
}

// EmbeddedContent returns the canonical signed content embedded in the
// object's annotations, if present. When present, the signature was computed
// over exactly these bytes and they are the verified source of truth — the
// object's own spec may have been normalised by the server since.
func EmbeddedContent(obj SignableObject) ([]byte, bool, error) {
	if obj == nil {
		return nil, false, fmt.Errorf("nil object")
	}
	annotations := obj.GetAnnotations()
	if annotations == nil {
		return nil, false, nil
	}
	enc, ok := annotations[AnnotationContent]
	if !ok {
		return nil, false, nil
	}
	content, err := decodeEmbeddedContent(enc)
	if err != nil {
		return nil, true, err
	}
	return content, true, nil
}

// embeddedIdentity is the metadata the embedded content commits to; used to
// bind the signed content to the carrier object it is stapled onto.
type embeddedIdentity struct {
	Metadata struct {
		Name      string  `json:"name"`
		Namespace *string `json:"namespace"`
	} `json:"metadata"`
}

// checkEmbeddedBinding binds the signed name and, when present, namespace to
// the carrier. Adapters omitting namespace keep their portable-artifact behavior.
// A mismatch is treated as tampering.
func checkEmbeddedBinding(obj SignableObject, embedded []byte) error {
	var id embeddedIdentity
	if err := json.Unmarshal(embedded, &id); err != nil {
		return fmt.Errorf("parse embedded metadata: %w", err)
	}
	if id.Metadata.Name != obj.GetName() {
		return fmt.Errorf("embedded content name %q does not match object %q", id.Metadata.Name, obj.GetName())
	}
	if id.Metadata.Namespace != nil && *id.Metadata.Namespace != obj.GetNamespace() {
		return fmt.Errorf("embedded content namespace %q does not match object %q", *id.Metadata.Namespace, obj.GetNamespace())
	}
	return nil
}
