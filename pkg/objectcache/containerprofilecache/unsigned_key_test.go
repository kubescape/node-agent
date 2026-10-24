//go:build experimental_signing

package containerprofilecache

import (
	"testing"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestUnsignedKeyIgnoresResourceVersion(t *testing.T) {
	a := &v1beta1.ContainerProfile{ObjectMeta: metav1.ObjectMeta{Namespace: "arc-systems", Name: "arc-runner-dind", ResourceVersion: "100"}}
	b := &v1beta1.ContainerProfile{ObjectMeta: metav1.ObjectMeta{Namespace: "arc-systems", Name: "arc-runner-dind", ResourceVersion: "101"}}
	other := &v1beta1.ContainerProfile{ObjectMeta: metav1.ObjectMeta{Namespace: "arc-systems", Name: "arc-runner", ResourceVersion: "100"}}
	assert.Equal(t, unsignedKey(a), unsignedKey(b))
	assert.NotEqual(t, unsignedKey(a), unsignedKey(other))
}
