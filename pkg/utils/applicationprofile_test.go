package utils

import (
	"testing"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Test_EnrichApplicationProfileContainer(t *testing.T) {

	applicationProfile := &v1beta1.ApplicationProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "replicaset-checkoutservice-59596bf8d8",
			Namespace:       "node-agent-test-veum",
			UID:             "b86e1667-ad01-4187-b6e5-61993e58a1d9",
			ResourceVersion: "1",
			Labels:          map[string]string{},
			Annotations:     map[string]string{},
		},
		Spec: v1beta1.ApplicationProfileSpec{
			Containers: []v1beta1.ApplicationProfileContainer{
				{
					Name:         "server",
					Capabilities: []string{"SETGID", "NET_ADMIN", "SYS_ADMIN", "SETPCAP", "SETUID"},
					Execs: []v1beta1.ExecCalls{
						{Path: "/checkoutservice", Args: []string{"/checkoutservice"}},
						{Path: "/bin/grpc_health_probe", Args: []string{"/bin/grpc_health_probe", "-addr=:5050"}},
					},
					Opens:    nil,
					Syscalls: []string{"nanosleep", "listen", "bind", "connect", "rt_sigaction"},
				},
			},
		},
		Status: struct{}{},
	}

	existingContainer := GetApplicationProfileContainer(applicationProfile, Container, 0)
	assert.NotNil(t, existingContainer)

	var test map[string]*v1beta1.HTTPEndpoint

	// empty enrich
	EnrichApplicationProfileContainer(existingContainer, []string{}, []string{}, map[string][]string{}, map[string]mapset.Set[string]{}, test)
	assert.Equal(t, 5, len(existingContainer.Capabilities))
	assert.Equal(t, 2, len(existingContainer.Execs))
	assert.Equal(t, 5, len(existingContainer.Syscalls))
	assert.Equal(t, 0, len(existingContainer.Opens))

	// enrich with existing capabilities, syscalls - no change
	EnrichApplicationProfileContainer(existingContainer, []string{"SETGID"}, []string{"listen"}, map[string][]string{}, map[string]mapset.Set[string]{}, test)
	assert.Equal(t, 5, len(existingContainer.Capabilities))
	assert.Equal(t, 2, len(existingContainer.Execs))
	assert.Equal(t, 5, len(existingContainer.Syscalls))
	assert.Equal(t, 0, len(existingContainer.Opens))

	// enrich with new capabilities, syscalls - add
	EnrichApplicationProfileContainer(existingContainer, []string{"NEW"}, []string{"xxx", "yyy"}, map[string][]string{}, map[string]mapset.Set[string]{}, test)
	assert.Equal(t, 6, len(existingContainer.Capabilities))
	assert.Equal(t, 2, len(existingContainer.Execs))
	assert.Equal(t, 7, len(existingContainer.Syscalls))
	assert.Equal(t, 0, len(existingContainer.Opens))

	// enrich with new opens
	opens := map[string]mapset.Set[string]{
		"/checkoutservice": mapset.NewSet("O_RDONLY", "O_WRONLY"),
	}
	EnrichApplicationProfileContainer(existingContainer, []string{"NEW"}, []string{"xxx", "yyy"}, map[string][]string{}, opens, test)
	assert.Equal(t, 6, len(existingContainer.Capabilities))
	assert.Equal(t, 2, len(existingContainer.Execs))
	assert.Equal(t, 7, len(existingContainer.Syscalls))
	assert.Equal(t, 1, len(existingContainer.Opens))
}
