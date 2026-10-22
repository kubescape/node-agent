//go:build experimental_signing

package bundle

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/kubescape/node-agent/pkg/signature"
)

const FixedRootKeyPath = "/etc/bundle/root.pub"

const signedConfigObjectName = "config"

type signedConfigArtifact struct {
	Config      json.RawMessage   `json:"config"`
	Annotations map[string]string `json:"annotations"`
}

type configSignable struct {
	raw         json.RawMessage
	content     interface{}
	annotations map[string]string
}

func canonicalConfigContent(raw []byte) (interface{}, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, errors.New("config payload is empty")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var content interface{}
	if err := dec.Decode(&content); err != nil {
		return nil, fmt.Errorf("parse config payload: %w", err)
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("config payload has trailing data after the JSON object")
	}
	if _, ok := content.(map[string]interface{}); !ok {
		return nil, errors.New("config payload is not a JSON object")
	}
	return content, nil
}

func newConfigSignable(raw json.RawMessage, annotations map[string]string) (*configSignable, error) {
	content, err := canonicalConfigContent(raw)
	if err != nil {
		return nil, err
	}
	if annotations == nil {
		annotations = make(map[string]string)
	}
	return &configSignable{raw: raw, content: content, annotations: annotations}, nil
}

func (c *configSignable) GetAnnotations() map[string]string { return c.annotations }

func (c *configSignable) SetAnnotations(a map[string]string) {
	if a == nil {
		a = make(map[string]string)
	}
	c.annotations = a
}

func (c *configSignable) GetUID() string          { return "" }
func (c *configSignable) GetNamespace() string    { return "" }
func (c *configSignable) GetName() string         { return signedConfigObjectName }
func (c *configSignable) GetContent() interface{} { return c.content }
func (c *configSignable) GetUpdatedObject() interface{} {
	return signedConfigArtifact{Config: c.raw, Annotations: c.annotations}
}

func SignConfig(raw []byte, rootKey *ecdsa.PrivateKey) ([]byte, error) {
	if rootKey == nil {
		return nil, errors.New("nil root key")
	}
	it, err := newConfigSignable(json.RawMessage(raw), nil)
	if err != nil {
		return nil, fmt.Errorf("sign config: %w", err)
	}
	if err := signature.SignObject(it, signature.WithPrivateKey(rootKey)); err != nil {
		return nil, fmt.Errorf("sign config: %w", err)
	}
	artifact := signedConfigArtifact{Config: it.raw, Annotations: it.GetAnnotations()}
	out, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal signed config: %w", err)
	}
	return out, nil
}

func verifyAndPinConfig(data []byte, expectedRootFp string) ([]byte, error) {
	var artifact signedConfigArtifact
	if err := json.Unmarshal(data, &artifact); err != nil {
		return nil, fmt.Errorf("parse signed config: %w", err)
	}
	payload := bytes.TrimSpace(artifact.Config)
	if len(payload) == 0 || bytes.Equal(payload, []byte("null")) {
		return nil, errors.New("signed config has no config payload")
	}
	if len(artifact.Annotations) == 0 {
		return nil, errors.New("signed config has no signature annotations")
	}
	if _, embedded := artifact.Annotations[signature.AnnotationContent]; embedded {
		return nil, fmt.Errorf("signed config carries an unexpected %s annotation", signature.AnnotationContent)
	}

	it, err := newConfigSignable(artifact.Config, artifact.Annotations)
	if err != nil {
		return nil, fmt.Errorf("signed config rejected: %w", err)
	}

	if err := signature.VerifyObjectAllowUntrusted(it); err != nil {
		return nil, fmt.Errorf("config signature verification failed: %w", err)
	}

	sig, err := signature.GetObjectSignature(it)
	if err != nil {
		return nil, fmt.Errorf("config signature verification failed: %w", err)
	}
	signer, err := signerIdentity(sig)
	if err != nil {
		return nil, fmt.Errorf("config signature verification failed: %w", err)
	}
	if signer != expectedRootFp {
		return nil, errors.New("config not signed by the pinned root key")
	}

	return artifact.Config, nil
}

func fixedRootFingerprint() (string, error) {
	fp, _, err := ResolveTrustedRootFingerprint()
	if err != nil {
		return "", fmt.Errorf("resolve root fingerprint: %w", err)
	}
	return fp, nil
}

func LoadSignedConfig(path string) ([]byte, error) {
	rootFp, err := fixedRootFingerprint()
	if err != nil {
		return nil, err
	}
	return loadSignedConfigWithRoot(path, rootFp)
}

func loadSignedConfigWithRoot(path, expectedRootFp string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signed config %q: %w", path, err)
	}
	verified, err := verifyAndPinConfig(b, expectedRootFp)
	if err != nil {
		return nil, fmt.Errorf("signed config %q: %w", path, err)
	}
	return verified, nil
}

func LoadSignedConfigIfPresent(path string) ([]byte, bool, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, true, fmt.Errorf("stat signed config %q: %w", path, err)
	}
	verified, err := LoadSignedConfig(path)
	if err != nil {
		return nil, true, err
	}
	return verified, true, nil
}
