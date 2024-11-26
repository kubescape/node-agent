package seccompmanager

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

//	func TestName(t *testing.T) {
//		var ap v1beta1.ApplicationProfile
//		file, err := os.ReadFile("../../../mocks/testdata/nginx_applicationprofiles.json")
//		assert.NoError(t, err)
//		err = json.Unmarshal(file, &ap)
//		assert.NoError(t, err)
//		ap.Spec.Containers[0].SeccompProfile.Path = "default/replicaset-nginx-bf5d5cf98-nginx.json"
//		file2, err := os.ReadFile("../../../seccomp/default/replicaset-nginx-bf5d5cf98-nginx.json")
//		assert.NoError(t, err)
//		err = json.Unmarshal(file2, &ap.Spec.Containers[0].SeccompProfile.Spec)
//		assert.NoError(t, err)
//		bytes, err := json.Marshal(ap)
//		assert.NoError(t, err)
//		err = os.WriteFile("../../../mocks/testdata/nginx_applicationprofiles.json", bytes, 0644)
//	}

//func TestName(t *testing.T) {
//	sp := v1beta1.SeccompProfile{
//		TypeMeta: metav1.TypeMeta{
//			Kind:       "SeccompProfile",
//			APIVersion: v1beta1.SchemeGroupVersion.String(),
//		},
//		ObjectMeta: metav1.ObjectMeta{
//			Name:      "replicaset-nginx-77b4fdf86c",
//			Namespace: "default",
//		},
//		Spec: v1beta1.SeccompProfileSpec{
//			Containers: []v1beta1.SingleSeccompProfile{{
//				Name: "nginx",
//				Path: "default/replicaset-nginx-77b4fdf86c-nginx.json",
//			}},
//		},
//	}
//	file, err := os.ReadFile("../../../mocks/testdata/nginx_seccomp_config.json")
//	assert.NoError(t, err)
//	err = json.Unmarshal(file, &sp.Spec.Containers[0].Spec)
//	assert.NoError(t, err)
//	bytes, err := json.Marshal(sp)
//	assert.NoError(t, err)
//	err = os.WriteFile("../../../mocks/testdata/nginx_seccompprofiles.json", bytes, 0644)
//	assert.NoError(t, err)
//}

func TestSeccompManager(t *testing.T) {
	tests := []struct {
		name    string
		obj     *unstructured.Unstructured
		path    string
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "create seccomp profile",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"kind": "SeccompProfile",
					"metadata": map[string]interface{}{
						"name":      "replicaset-nginx-77b4fdf86c",
						"namespace": "default",
					},
					"spec": map[string]interface{}{
						"containers": []map[string]interface{}{
							{
								"name": "nginx",
								"path": "default/replicaset-nginx-77b4fdf86c-nginx.json",
							},
						},
					},
				},
			},
			path:    "default/replicaset-nginx-77b4fdf86c-nginx.json",
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &SeccompManager{
				appFs:              afero.NewMemMapFs(),
				seccompProfilesDir: "/seccomp",
			}
			err := s.AddSeccompProfile(tt.obj)
			tt.wantErr(t, err)
			_, err = s.appFs.Stat(filepath.Join(s.seccompProfilesDir, tt.path))
			assert.NoError(t, err)
			_, err = s.GetSeccompProfile("replicaset-nginx-77b4fdf86c", &tt.path)
			assert.NoError(t, err)
			err = s.DeleteSeccompProfile(tt.obj)
			tt.wantErr(t, err)
			_, err = s.appFs.Stat(filepath.Join(s.seccompProfilesDir, tt.path))
			assert.Error(t, err)
		})
	}
}

func Test_getProfilesDir(t *testing.T) {
	tests := []struct {
		name        string
		hostRoot    string
		kubeletRoot string
		want        string
		wantErr     assert.ErrorAssertionFunc
	}{
		{
			name:    "default values",
			want:    "/host/var/lib/kubelet/seccomp",
			wantErr: assert.NoError,
		},
		{
			name:     "set HOST_ROOT",
			hostRoot: "/host2",
			want:     "/host2/var/lib/kubelet/seccomp",
			wantErr:  assert.NoError,
		},
		{
			name:        "set KUBELET_ROOT",
			kubeletRoot: "/var/lib/kubelet2",
			want:        "/host/var/lib/kubelet2/seccomp",
			wantErr:     assert.NoError,
		},
		{
			name:        "set HOST_ROOT and KUBELET_ROOT",
			hostRoot:    "/host2",
			kubeletRoot: "/var/lib/kubelet2",
			want:        "/host2/var/lib/kubelet2/seccomp",
			wantErr:     assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.hostRoot != "" {
				t.Setenv("HOST_ROOT", tt.hostRoot)
			}
			if tt.kubeletRoot != "" {
				t.Setenv("KUBELET_ROOT", tt.kubeletRoot)
			}
			got, err := getProfilesDir()
			if !tt.wantErr(t, err, fmt.Sprintf("getProfilesDir()")) {
				return
			}
			assert.Equalf(t, tt.want, got, "getProfilesDir()")
		})
	}
}
