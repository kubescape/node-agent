//go:build experimental_signing

package signature

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand"
	"testing"

	rulemanagertypesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func diffKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	return k
}

func refVerifyAccepts(obj SignableObject) (bool, error) {
	ann := obj.GetAnnotations()
	if ann == nil {
		return false, fmt.Errorf("no annotations")
	}
	sigB64, ok := ann[AnnotationSignature]
	if !ok {
		return false, fmt.Errorf("no signature annotation")
	}
	certB64, ok := ann[AnnotationCertificate]
	if !ok {
		return false, fmt.Errorf("no certificate annotation")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false, fmt.Errorf("signature not base64: %w", err)
	}
	certBytes, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return false, fmt.Errorf("certificate not base64: %w", err)
	}
	block, _ := pem.Decode(certBytes)
	if block == nil {
		return false, fmt.Errorf("certificate not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("parse certificate: %w", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("certificate key is not ECDSA")
	}
	var hash string
	if enc, present := ann[AnnotationContent]; present {
		gz, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			return false, fmt.Errorf("embedded content not base64: %w", err)
		}
		zr, err := gzip.NewReader(bytes.NewReader(gz))
		if err != nil {
			return false, fmt.Errorf("embedded content not gzip: %w", err)
		}
		embedded, err := io.ReadAll(zr)
		if err != nil {
			return false, fmt.Errorf("embedded content unreadable: %w", err)
		}
		var id struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(embedded, &id); err != nil {
			return false, fmt.Errorf("embedded metadata unparsable: %w", err)
		}
		if id.Metadata.Name != obj.GetName() {
			return false, fmt.Errorf("embedded content bound to a different name")
		}
		hash, err = utils.CanonicalHash(embedded)
		if err != nil {
			return false, fmt.Errorf("hash embedded: %w", err)
		}
	} else {
		raw, err := json.Marshal(obj.GetContent())
		if err != nil {
			return false, fmt.Errorf("marshal content: %w", err)
		}
		hash, err = utils.CanonicalHash(raw)
		if err != nil {
			return false, fmt.Errorf("hash content: %w", err)
		}
	}
	digest := sha256.Sum256([]byte(hash))
	return ecdsa.VerifyASN1(pub, digest[:], sigBytes), nil
}

func randomCP(rng *mathrand.Rand, name string) *v1beta1.ContainerProfile {
	spec := v1beta1.ContainerProfileSpec{}
	for _, a := range []string{"amd64", "arm64", "386"} {
		if rng.Intn(2) == 0 {
			spec.Architectures = append(spec.Architectures, a)
		}
	}
	if len(spec.Architectures) == 0 {
		spec.Architectures = []string{"amd64"}
	}
	for _, c := range []string{"CAP_NET_ADMIN", "CAP_SYS_PTRACE", "CAP_CHOWN"} {
		if rng.Intn(2) == 0 {
			spec.Capabilities = append(spec.Capabilities, c)
		}
	}
	nExec := rng.Intn(3) + 1
	for e := 0; e < nExec; e++ {
		spec.Execs = append(spec.Execs, v1beta1.ExecCalls{
			Path: fmt.Sprintf("/bin/tool-%d-%d", rng.Intn(1000), e),
			Args: []string{fmt.Sprintf("arg%d", rng.Intn(100))},
		})
	}
	if rng.Intn(2) == 0 {
		spec.Opens = append(spec.Opens, v1beta1.OpenCalls{Path: fmt.Sprintf("/data/f-%d", rng.Intn(1000)), Flags: []string{"O_RDONLY"}})
	}
	for _, s := range []string{"read", "write", "openat", "close", "connect"} {
		if rng.Intn(2) == 0 {
			spec.Syscalls = append(spec.Syscalls, s)
		}
	}
	return &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: fmt.Sprintf("ns-%d", rng.Intn(1000)),
			Labels: map[string]string{
				"app":  fmt.Sprintf("app-%d", rng.Intn(1000)),
				"tier": fmt.Sprintf("tier-%d", rng.Intn(10)),
			},
		},
		Spec: spec,
	}
}

func randomRules(rng *mathrand.Rand, name string) *rulemanagertypesv1.Rules {
	var rules []rulemanagertypesv1.Rule
	n := rng.Intn(4) + 1
	for i := 0; i < n; i++ {
		rules = append(rules, rulemanagertypesv1.Rule{
			Enabled:  rng.Intn(2) == 0,
			ID:       fmt.Sprintf("R%04d", rng.Intn(9999)),
			Name:     fmt.Sprintf("rule-%d", rng.Intn(1000)),
			Severity: rng.Intn(10),
		})
	}
	return &rulemanagertypesv1.Rules{
		TypeMeta: metav1.TypeMeta{APIVersion: "kubescape.io/v1", Kind: "Rules"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: fmt.Sprintf("ns-%d", rng.Intn(1000)),
			Labels:    map[string]string{"app": fmt.Sprintf("app-%d", rng.Intn(1000))},
		},
		Spec: rulemanagertypesv1.RulesSpec{Rules: rules},
	}
}

func TestDifferential_IndependentVerifierAgreesOnAccept(t *testing.T) {
	rng := mathrand.New(mathrand.NewSource(0x5321BEEF))
	const iterations = 80
	agreed := 0
	for i := 0; i < iterations; i++ {
		for _, embed := range []bool{false, true} {
			opts := []SignOption{WithPrivateKey(diffKey(t))}
			if embed {
				opts = append(opts, WithEmbedContent(true))
			}

			cp := randomCP(rng, fmt.Sprintf("cp-%d", i))
			cpObj := profiles.NewContainerProfileAdapter(cp)
			if err := SignObject(cpObj, opts...); err != nil {
				t.Fatalf("sign cp %d embed=%v: %v", i, embed, err)
			}
			refOK, refErr := refVerifyAccepts(cpObj)
			prodOK := VerifyObjectAllowUntrusted(cpObj) == nil
			if !refOK || !prodOK || refOK != prodOK {
				t.Fatalf("cp %d embed=%v: stdlib ref accept=%v (err=%v), production accept=%v — must both accept and agree", i, embed, refOK, refErr, prodOK)
			}
			agreed++

			r := randomRules(rng, fmt.Sprintf("rules-%d", i))
			rObj := profiles.NewRulesAdapter(r)
			ropts := []SignOption{WithPrivateKey(diffKey(t))}
			if embed {
				ropts = append(ropts, WithEmbedContent(true))
			}
			if err := SignObject(rObj, ropts...); err != nil {
				t.Fatalf("sign rules %d embed=%v: %v", i, embed, err)
			}
			refOK, refErr = refVerifyAccepts(rObj)
			prodOK = VerifyObjectAllowUntrusted(rObj) == nil
			if !refOK || !prodOK || refOK != prodOK {
				t.Fatalf("rules %d embed=%v: stdlib ref accept=%v (err=%v), production accept=%v — must both accept and agree", i, embed, refOK, refErr, prodOK)
			}
			agreed++
		}
	}
	t.Logf("independent stdlib verifier agreed with production on %d freshly signed objects (CP+Rules, embed and non-embed)", agreed)
}

func flipMiddleByteB64(t *testing.T, b64 string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode for flip: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("cannot flip an empty value")
	}
	raw[len(raw)/2] ^= 0xFF
	return base64.StdEncoding.EncodeToString(raw)
}

func truncateB64(t *testing.T, b64 string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode for truncate: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw[:len(raw)/2])
}

type cpMutation struct {
	name  string
	embed bool
	apply func(t *testing.T, cp *v1beta1.ContainerProfile)
	want  error
}

func TestDifferential_MutationOracle(t *testing.T) {
	otherKey := diffKey(t)
	otherCP := &v1beta1.ContainerProfile{ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "x"}}
	if err := SignObject(profiles.NewContainerProfileAdapter(otherCP), WithPrivateKey(otherKey)); err != nil {
		t.Fatalf("sign other: %v", err)
	}
	otherCert := otherCP.Annotations[AnnotationCertificate]

	mutations := []cpMutation{
		{"flip a signature byte", false, func(t *testing.T, cp *v1beta1.ContainerProfile) {
			cp.Annotations[AnnotationSignature] = flipMiddleByteB64(t, cp.Annotations[AnnotationSignature])
		}, ErrSignatureMismatch},
		{"flip a certificate byte", false, func(t *testing.T, cp *v1beta1.ContainerProfile) {
			cp.Annotations[AnnotationCertificate] = flipMiddleByteB64(t, cp.Annotations[AnnotationCertificate])
		}, ErrSignatureMismatch},
		{"replace certificate with a different key's cert", false, func(t *testing.T, cp *v1beta1.ContainerProfile) {
			cp.Annotations[AnnotationCertificate] = otherCert
		}, ErrSignatureMismatch},
		{"truncate the signature", false, func(t *testing.T, cp *v1beta1.ContainerProfile) {
			cp.Annotations[AnnotationSignature] = truncateB64(t, cp.Annotations[AnnotationSignature])
		}, ErrSignatureMismatch},
		{"drop the signature annotation", false, func(t *testing.T, cp *v1beta1.ContainerProfile) {
			delete(cp.Annotations, AnnotationSignature)
		}, ErrObjectNotSigned},
		{"drop the certificate annotation", false, func(t *testing.T, cp *v1beta1.ContainerProfile) {
			delete(cp.Annotations, AnnotationCertificate)
		}, ErrSignatureMismatch},
		{"mutate a spec field after signing", false, func(t *testing.T, cp *v1beta1.ContainerProfile) {
			cp.Spec.Architectures = append(cp.Spec.Architectures, "zzz-injected")
		}, ErrSignatureMismatch},
		{"add a metadata label after signing", false, func(t *testing.T, cp *v1beta1.ContainerProfile) {
			cp.Labels["zzz-added"] = "1"
		}, ErrSignatureMismatch},
		{"remove a metadata label after signing", false, func(t *testing.T, cp *v1beta1.ContainerProfile) {
			delete(cp.Labels, "app")
		}, ErrSignatureMismatch},
		{"change a metadata label after signing", false, func(t *testing.T, cp *v1beta1.ContainerProfile) {
			cp.Labels["app"] = "changed"
		}, ErrSignatureMismatch},
		{"flip a signature byte (embedded)", true, func(t *testing.T, cp *v1beta1.ContainerProfile) {
			cp.Annotations[AnnotationSignature] = flipMiddleByteB64(t, cp.Annotations[AnnotationSignature])
		}, ErrSignatureMismatch},
		{"flip a certificate byte (embedded)", true, func(t *testing.T, cp *v1beta1.ContainerProfile) {
			cp.Annotations[AnnotationCertificate] = flipMiddleByteB64(t, cp.Annotations[AnnotationCertificate])
		}, ErrSignatureMismatch},
		{"replace certificate (embedded)", true, func(t *testing.T, cp *v1beta1.ContainerProfile) {
			cp.Annotations[AnnotationCertificate] = otherCert
		}, ErrSignatureMismatch},
		{"truncate the signature (embedded)", true, func(t *testing.T, cp *v1beta1.ContainerProfile) {
			cp.Annotations[AnnotationSignature] = truncateB64(t, cp.Annotations[AnnotationSignature])
		}, ErrSignatureMismatch},
		{"drop the signature annotation (embedded)", true, func(t *testing.T, cp *v1beta1.ContainerProfile) {
			delete(cp.Annotations, AnnotationSignature)
		}, ErrObjectNotSigned},
		{"drop the certificate annotation (embedded)", true, func(t *testing.T, cp *v1beta1.ContainerProfile) {
			delete(cp.Annotations, AnnotationCertificate)
		}, ErrSignatureMismatch},
		{"mutate a byte of the embedded content", true, func(t *testing.T, cp *v1beta1.ContainerProfile) {
			cp.Annotations[AnnotationContent] = flipMiddleByteB64(t, cp.Annotations[AnnotationContent])
		}, ErrSignatureMismatch},
	}

	rng := mathrand.New(mathrand.NewSource(0x0BADC0DE))
	const baseObjects = 12
	checks := 0
	for i := 0; i < baseObjects; i++ {
		template := randomCP(rng, fmt.Sprintf("mut-cp-%d", i))
		key := diffKey(t)
		for _, m := range mutations {
			cp := template.DeepCopy()
			opts := []SignOption{WithPrivateKey(key)}
			if m.embed {
				opts = append(opts, WithEmbedContent(true))
			}
			adapter := profiles.NewContainerProfileAdapter(cp)
			if err := SignObject(adapter, opts...); err != nil {
				t.Fatalf("sign base %d for %q: %v", i, m.name, err)
			}
			if err := VerifyObjectAllowUntrusted(adapter); err != nil {
				t.Fatalf("precondition base %d %q: pristine object must verify, got %v", i, m.name, err)
			}

			m.apply(t, cp)

			err := VerifyObjectAllowUntrusted(adapter)
			if err == nil {
				t.Fatalf("base %d mutation %q: production ACCEPTED a mutated object", i, m.name)
			}
			if !errors.Is(err, m.want) {
				t.Fatalf("base %d mutation %q: want errors.Is(%v), got %v", i, m.name, m.want, err)
			}
			if refOK, _ := refVerifyAccepts(adapter); refOK {
				t.Fatalf("base %d mutation %q: independent stdlib verifier ACCEPTED a mutated object", i, m.name)
			}
			checks++
		}
	}
	t.Logf("mutation oracle: %d mutated objects across %d base objects, all rejected by BOTH the independent stdlib verifier and production with the expected sentinel", checks, baseObjects)
}
