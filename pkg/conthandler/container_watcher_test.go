package conthandler

import (
	conthandlerV1 "node-agent/pkg/conthandler/v1"
	"testing"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

type k8sFakeClient struct {
	Clientset *fake.Clientset
}

func (client *k8sFakeClient) GetK8sConfig() *rest.Config {
	return nil
}

func (client *k8sFakeClient) CalculateWorkloadParentRecursive(_ any) (string, string, error) {
	return "deployment", "nginx", nil
}

func (client *k8sFakeClient) GetWorkload(_, _, _ string) (any, error) {
	return &workloadinterface.Workload{}, nil
}

func (client *k8sFakeClient) GenerateWLID(_ any, clusterName string) string {
	return "wlid://cluster-" + clusterName + "/namespace-any" + "/deployment-nginx"
}

func TestCreateContainerClientK8SAPIServer(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name: "TestCreateContainerClientK8SAPIServer",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CreateContainerClientK8SAPIServer()
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateContainerClientK8SAPIServer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.NotNil(t, got.GetK8sConfig())
		})
	}
}

func TestContainerWatcher_ParsePodData(t *testing.T) {
	type fields struct {
		ContainerClient ContainerClient
		clusterName     string
	}
	type args struct {
		pod       *workloadinterface.Workload
		container *containercollection.Container
	}
	pod, err := workloadinterface.NewWorkload([]byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"nginx","namespace":"default"},"spec":{"containers":[{"name":"nginx","image":"nginx:1.14.2"}]}}`))
	instanceID := &instanceidhandler.InstanceID{}
	instanceID.SetAPIVersion("v1")
	instanceID.SetNamespace("default")
	instanceID.SetKind("Pod")
	instanceID.SetName("nginx")
	instanceID.SetContainerName("nginx")
	assert.NoError(t, err)
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *conthandlerV1.ContainerEventData
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "TestContainerWatcher_ParsePodData",
			args: args{
				pod:       pod,
				container: &containercollection.Container{Name: "nginx"},
			},
			fields: fields{
				ContainerClient: &k8sFakeClient{},
				clusterName:     "test",
			},
			want: conthandlerV1.CreateNewContainerEvent("nginx:1.14.2", &containercollection.Container{Name: "nginx"}, "default/nginx/nginx", "wlid://cluster-test/namespace-any/deployment-nginx", instanceID),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			containerWatcher := &ContainerWatcher{
				ContainerClient: tt.fields.ContainerClient,
				clusterName:     tt.fields.clusterName,
			}
			got, err := containerWatcher.ParsePodData(tt.args.pod, tt.args.container)
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
