//go:build experimental_signing

package containerprofilecache

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"os"
	"strings"
	"testing"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func captureLogs(t *testing.T, fn func()) string {
	t.Helper()
	origStderr, origStdout := os.Stderr, os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr, os.Stdout = w, w
	logger.InitLogger("pretty")
	fn()
	w.Close()
	os.Stderr, os.Stdout = origStderr, origStdout
	logger.InitLogger("pretty")
	b, _ := io.ReadAll(r)
	return string(b)
}

func testECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return k
}

func signedEmbeddedCP(t *testing.T) *v1beta1.ContainerProfile {
	t.Helper()
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "frag", Namespace: "redis", Labels: map[string]string{
			"signature.kubescape.io/bundle": "redis", "signature.kubescape.io/fragment-class": "base"}},
		Spec: v1beta1.ContainerProfileSpec{Execs: []v1beta1.ExecCalls{{Path: "/bin/x"}}},
	}
	require.NoError(t, signature.SignObject(profiles.NewContainerProfileAdapter(cp), signature.WithPrivateKey(testECDSAKey(t)), signature.WithEmbedContent(true)))
	return cp
}

// One warning per distinct stored content; a clean pass re-arms; a new
// distinct edit warns again (AC #70-3).
func TestReportSpecDivergence_DedupAndRearm(t *testing.T) {
	c := &ContainerProfileCacheImpl{}
	cp := signedEmbeddedCP(t)
	key := "bundle/redis/redis/frag"

	out := captureLogs(t, func() { c.reportSpecDivergence(key, cp, "redis", "redis") })
	require.NotContains(t, out, "diverges", "clean fragment must not warn")

	cp.Spec.Execs = append(cp.Spec.Execs, v1beta1.ExecCalls{Path: "/bin/backdoor"})
	out = captureLogs(t, func() {
		c.reportSpecDivergence(key, cp, "redis", "redis")
		c.reportSpecDivergence(key, cp, "redis", "redis")
		c.reportSpecDivergence(key, cp, "redis", "redis")
	})
	require.Equal(t, 1, strings.Count(out, "stored spec diverges"), "same stored content must warn exactly once")
	require.Contains(t, out, "execs")
	require.NotContains(t, out, "/bin/backdoor", "spec values must never reach the log")

	cp.Spec.Execs = cp.Spec.Execs[:1]
	out = captureLogs(t, func() { c.reportSpecDivergence(key, cp, "redis", "redis") })
	require.NotContains(t, out, "diverges", "reverting must clear, not warn")

	cp.Spec.Execs = append(cp.Spec.Execs, v1beta1.ExecCalls{Path: "/bin/other"})
	out = captureLogs(t, func() { c.reportSpecDivergence(key, cp, "redis", "redis") })
	require.Equal(t, 1, strings.Count(out, "stored spec diverges"), "a distinct later edit must warn again")
}
