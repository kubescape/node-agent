package applicationprofilecache

import (
	"context"
	"node-agent/pkg/ruleengine/objectcache"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func Test_unstructuredToApplicationProfile(t *testing.T) {

	tests := []struct {
		name string
		obj  *unstructured.Unstructured
	}{
		{
			name: "nginx application profile",
			obj:  objectcache.GetUnstructured(objectcache.TestKindAP, objectcache.TestNginx),
		},
		{
			name: "collection application profile",
			obj:  objectcache.GetUnstructured(objectcache.TestKindAP, objectcache.TestCollection),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := unstructuredToApplicationProfile(tt.obj)
			assert.NoError(t, err)
			assert.Equal(t, tt.obj.GetName(), p.GetName())
			assert.Equal(t, tt.obj.GetLabels(), p.GetLabels())
		})
	}
}

func Test_getApplicationProfile(t *testing.T) {
	type args struct {
		name      string
		namespace string
	}
	tests := []struct {
		name    string
		obj     *unstructured.Unstructured
		args    args
		wantErr bool
	}{
		{
			name: "nginx application profile",
			obj:  objectcache.GetUnstructured(objectcache.TestKindAP, objectcache.TestNginx),
			args: args{
				name:      "replicaset-nginx-77b4fdf86c",
				namespace: "default",
			},
			wantErr: false,
		},
		{
			name: "collection application profile",
			obj:  objectcache.GetUnstructured(objectcache.TestKindAP, objectcache.TestCollection),
			args: args{
				name:      "replicaset-collection-94c495554",
				namespace: "collection",
			},
			wantErr: false,
		},
		{
			name: "collection application profile",
			obj:  objectcache.GetUnstructured(objectcache.TestKindAP, objectcache.TestCollection),
			args: args{
				name:      "replicaset-nginx-77b4fdf86c",
				namespace: "collection",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ap := &ApplicationProfileCacheImpl{
				k8sClient: k8sinterface.NewKubernetesApiMock(),
			}
			ap.k8sClient.GetDynamicClient().Resource(groupVersionResource).Create(context.Background(), &unstructured.Unstructured{Object: map[string]interface{}{}}, metav1.CreateOptions{})
			ap.k8sClient.GetDynamicClient().Resource(groupVersionResource).Namespace(tt.args.namespace).Create(context.Background(), tt.obj, metav1.CreateOptions{})

			a, err := ap.getApplicationProfile(tt.args.name, tt.args.namespace)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.obj.GetName(), a.GetName())
			assert.Equal(t, tt.obj.GetLabels(), a.GetLabels())
		})
	}
}
