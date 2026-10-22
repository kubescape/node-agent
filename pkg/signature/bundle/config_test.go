//go:build experimental_signing

package bundle

import (
	"crypto/ecdsa"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/kubescape/node-agent/pkg/signature"
)

const nodeAgentConfigJSON = `{
  "applicationProfileServiceEnabled": true,
  "runtimeDetectionEnabled": true,
  "enableSignatureVerification": true,
  "bundleTrustPolicyPath": "/etc/bundle/trust-policy.signed.json",
  "bundleRootKeyPath": "/etc/bundle/root.pub",
  "maxSniffingTimePerContainer": "24h",
  "excludeNamespaces": ["kube-system", "kubescape"],
  "eventDedup": {"enabled": true, "slotsExponent": 18},
  "maxTsProfileSize": 2097152
}`

const clusterDataJSON = `{
  "accountID": "11111111-2222-3333-4444-555555555555",
  "clusterName": "demo-cluster",
  "gatewayWebsocketURL": "gateway:8001",
  "kubevulnURL": "kubevuln:8080",
  "namespace": "kubescape",
  "eventReceiverRestURL": "https://report.example.invalid"
}`

func signConfigWithFingerprint(t *testing.T, raw string, key *ecdsa.PrivateKey) (signed []byte, fingerprint string) {
	t.Helper()
	signed, err := SignConfig([]byte(raw), key)
	if err != nil {
		t.Fatalf("SignConfig: %v", err)
	}
	var artifact signedConfigArtifact
	if err := json.Unmarshal(signed, &artifact); err != nil {
		t.Fatalf("unmarshal artifact: %v", err)
	}
	it, err := newConfigSignable(artifact.Config, artifact.Annotations)
	if err != nil {
		t.Fatalf("newConfigSignable: %v", err)
	}
	sig, err := signature.GetObjectSignature(it)
	if err != nil {
		t.Fatalf("get signature: %v", err)
	}
	fp, err := signerIdentity(sig)
	if err != nil {
		t.Fatalf("signer identity: %v", err)
	}
	return signed, fp
}

func decodeJSON(t *testing.T, b []byte) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal json: %v", err)
	}
	return m
}

func TestSignedConfig_RoundTripNodeAgentConfig(t *testing.T) {
	signed, fp := signConfigWithFingerprint(t, nodeAgentConfigJSON, genKey(t))

	got, err := verifyAndPinConfig(signed, fp)
	if err != nil {
		t.Fatalf("verifyAndPinConfig: %v", err)
	}
	if !reflect.DeepEqual(decodeJSON(t, got), decodeJSON(t, []byte(nodeAgentConfigJSON))) {
		t.Fatalf("verified config differs from the signed input: %s", string(got))
	}
}

func TestSignedConfig_RoundTripClusterData(t *testing.T) {
	signed, fp := signConfigWithFingerprint(t, clusterDataJSON, genKey(t))

	got, err := verifyAndPinConfig(signed, fp)
	if err != nil {
		t.Fatalf("verifyAndPinConfig: %v", err)
	}
	if !reflect.DeepEqual(decodeJSON(t, got), decodeJSON(t, []byte(clusterDataJSON))) {
		t.Fatalf("verified clusterData differs from the signed input: %s", string(got))
	}
}

func TestSignedConfig_WhitespaceAndKeyOrderInsensitive(t *testing.T) {
	key := genKey(t)
	signed, fp := signConfigWithFingerprint(t, nodeAgentConfigJSON, key)

	var artifact signedConfigArtifact
	if err := json.Unmarshal(signed, &artifact); err != nil {
		t.Fatalf("unmarshal artifact: %v", err)
	}

	reordered := `{"eventDedup":{"slotsExponent":18,"enabled":true},"maxTsProfileSize":2097152,` +
		`"excludeNamespaces":["kube-system","kubescape"],"bundleRootKeyPath":"/etc/bundle/root.pub",` +
		`"maxSniffingTimePerContainer":"24h","bundleTrustPolicyPath":"/etc/bundle/trust-policy.signed.json",` +
		`"enableSignatureVerification":true,"runtimeDetectionEnabled":true,"applicationProfileServiceEnabled":true}`

	if string(artifact.Config) == reordered {
		t.Fatal("test is not exercising re-serialisation: payload bytes are identical")
	}

	artifact.Config = json.RawMessage(reordered)
	reserialised, err := json.Marshal(artifact)
	if err != nil {
		t.Fatalf("marshal artifact: %v", err)
	}

	got, err := verifyAndPinConfig(reserialised, fp)
	if err != nil {
		t.Fatalf("re-serialised config must still verify: %v", err)
	}
	if !reflect.DeepEqual(decodeJSON(t, got), decodeJSON(t, []byte(nodeAgentConfigJSON))) {
		t.Fatalf("verified config differs from the signed input: %s", string(got))
	}
}

func TestSignedConfig_WrongSignerRejected(t *testing.T) {
	signed, _ := signConfigWithFingerprint(t, nodeAgentConfigJSON, genKey(t))
	_, otherFp := signConfigWithFingerprint(t, nodeAgentConfigJSON, genKey(t))

	_, err := verifyAndPinConfig(signed, otherFp)
	if err == nil {
		t.Fatal("config signed by a foreign key must be rejected")
	}
	if !strings.Contains(err.Error(), "not signed by the pinned root key") {
		t.Fatalf("expected a pinning error, got: %v", err)
	}
}

func TestSignedConfig_TamperedPayloadRejected(t *testing.T) {
	signed, fp := signConfigWithFingerprint(t, nodeAgentConfigJSON, genKey(t))

	var artifact signedConfigArtifact
	if err := json.Unmarshal(signed, &artifact); err != nil {
		t.Fatalf("unmarshal artifact: %v", err)
	}
	payload := decodeJSON(t, artifact.Config)
	payload["enableSignatureVerification"] = false
	tampered, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal tampered payload: %v", err)
	}
	artifact.Config = json.RawMessage(tampered)
	tamperedArtifact, err := json.Marshal(artifact)
	if err != nil {
		t.Fatalf("marshal artifact: %v", err)
	}

	_, err = verifyAndPinConfig(tamperedArtifact, fp)
	if err == nil {
		t.Fatal("tampered config payload must be rejected")
	}
	if !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("expected a signature verification error, got: %v", err)
	}
}

func TestSignedConfig_TamperedTrustPolicyPathRejected(t *testing.T) {
	signed, fp := signConfigWithFingerprint(t, nodeAgentConfigJSON, genKey(t))
	redirected := strings.Replace(string(signed), "/etc/bundle/trust-policy.signed.json", "/tmp/attacker-policy.json", 1)
	if redirected == string(signed) {
		t.Fatal("test setup failed: trust policy path not present in artifact")
	}

	_, err := verifyAndPinConfig([]byte(redirected), fp)
	if err == nil {
		t.Fatal("redirecting bundleTrustPolicyPath must be rejected")
	}
}

func TestSignedConfig_MissingAnnotationsRejected(t *testing.T) {
	signed, fp := signConfigWithFingerprint(t, nodeAgentConfigJSON, genKey(t))

	var artifact signedConfigArtifact
	if err := json.Unmarshal(signed, &artifact); err != nil {
		t.Fatalf("unmarshal artifact: %v", err)
	}
	artifact.Annotations = nil
	stripped, err := json.Marshal(artifact)
	if err != nil {
		t.Fatalf("marshal artifact: %v", err)
	}

	_, err = verifyAndPinConfig(stripped, fp)
	if err == nil {
		t.Fatal("config without signature annotations must be rejected")
	}
	if !strings.Contains(err.Error(), "no signature annotations") {
		t.Fatalf("expected a missing-annotations error, got: %v", err)
	}
}

func TestSignedConfig_MissingPayloadRejected(t *testing.T) {
	signed, fp := signConfigWithFingerprint(t, nodeAgentConfigJSON, genKey(t))

	var artifact signedConfigArtifact
	if err := json.Unmarshal(signed, &artifact); err != nil {
		t.Fatalf("unmarshal artifact: %v", err)
	}
	artifact.Config = nil
	stripped, err := json.Marshal(artifact)
	if err != nil {
		t.Fatalf("marshal artifact: %v", err)
	}

	_, err = verifyAndPinConfig(stripped, fp)
	if err == nil {
		t.Fatal("config artifact without a payload must be rejected")
	}
	if !strings.Contains(err.Error(), "no config payload") {
		t.Fatalf("expected a missing-payload error, got: %v", err)
	}
}

func TestSignedConfig_EmbeddedContentAnnotationRejected(t *testing.T) {
	signed, fp := signConfigWithFingerprint(t, nodeAgentConfigJSON, genKey(t))

	var artifact signedConfigArtifact
	if err := json.Unmarshal(signed, &artifact); err != nil {
		t.Fatalf("unmarshal artifact: %v", err)
	}
	artifact.Annotations[signature.AnnotationContent] = "c3RhcGxlZA=="
	stapled, err := json.Marshal(artifact)
	if err != nil {
		t.Fatalf("marshal artifact: %v", err)
	}

	_, err = verifyAndPinConfig(stapled, fp)
	if err == nil {
		t.Fatal("config artifact carrying embedded content must be rejected")
	}
	if !strings.Contains(err.Error(), signature.AnnotationContent) {
		t.Fatalf("expected an embedded-content error, got: %v", err)
	}
}

func TestSignedConfig_NonObjectPayloadRejected(t *testing.T) {
	key := genKey(t)
	if _, err := SignConfig([]byte(`["not", "an", "object"]`), key); err == nil {
		t.Fatal("a non-object config payload must not be signable")
	}
	if _, err := SignConfig([]byte(`{"a":1} {"b":2}`), key); err == nil {
		t.Fatal("trailing data after the config object must not be signable")
	}
	if _, err := SignConfig([]byte(``), key); err == nil {
		t.Fatal("an empty config payload must not be signable")
	}
}

func TestSignedConfig_LoadIfPresentAbsent(t *testing.T) {
	got, present, err := LoadSignedConfigIfPresent(t.TempDir() + "/config.signed.json")
	if err != nil {
		t.Fatalf("absent signed config must not error: %v", err)
	}
	if present {
		t.Fatal("absent signed config must report present=false")
	}
	if got != nil {
		t.Fatalf("absent signed config must return no bytes, got %s", string(got))
	}
}

func TestSignedConfig_LoadIfPresentRefusesForeignKey(t *testing.T) {
	signed, _ := signConfigWithFingerprint(t, nodeAgentConfigJSON, genKey(t))
	path := t.TempDir() + "/config.signed.json"
	if err := os.WriteFile(path, signed, 0644); err != nil {
		t.Fatalf("write signed config: %v", err)
	}

	_, present, err := LoadSignedConfigIfPresent(path)
	if !present {
		t.Fatal("an existing signed config must report present=true")
	}
	if err == nil {
		t.Fatal("a signed config not signed by the pinned root key must be refused")
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("refusal must name the file, got: %v", err)
	}
}

func TestSignedConfig_RoundTripFile(t *testing.T) {
	signed, fp := signConfigWithFingerprint(t, clusterDataJSON, genKey(t))
	path := t.TempDir() + "/clusterData.signed.json"
	if err := os.WriteFile(path, signed, 0644); err != nil {
		t.Fatalf("write signed config: %v", err)
	}

	got, err := loadSignedConfigWithRoot(path, fp)
	if err != nil {
		t.Fatalf("loadSignedConfigWithRoot: %v", err)
	}
	if !reflect.DeepEqual(decodeJSON(t, got), decodeJSON(t, []byte(clusterDataJSON))) {
		t.Fatalf("verified clusterData differs from the signed input: %s", string(got))
	}
}

func TestSignedConfig_FileTamperRejectedWithPath(t *testing.T) {
	signed, fp := signConfigWithFingerprint(t, clusterDataJSON, genKey(t))
	tampered := strings.Replace(string(signed), "demo-cluster", "attacker-cluster", 1)
	if tampered == string(signed) {
		t.Fatal("test setup failed: cluster name not present in artifact")
	}
	path := t.TempDir() + "/clusterData.signed.json"
	if err := os.WriteFile(path, []byte(tampered), 0644); err != nil {
		t.Fatalf("write signed config: %v", err)
	}

	_, err := loadSignedConfigWithRoot(path, fp)
	if err == nil {
		t.Fatal("a tampered clusterData file must be refused")
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("refusal must name the file, got: %v", err)
	}
}
