package profilevalidator

import (
	"testing"

	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"k8s.io/utils/ptr"
)

func TestNewProfileRegistry(t *testing.T) {
	objCache := &RuleObjectCacheMock{}

	registry := NewProfileRegistry(objCache)

	assert.NotNil(t, registry)
	assert.IsType(t, &ProfileRegistryImpl{}, registry)
}

func TestGetAvailableProfiles_Success(t *testing.T) {
	objCache := &RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}

	// Set up application profile
	profile := &v1beta1.ApplicationProfile{}
	profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
		Name: "test-container",
		Execs: []v1beta1.ExecCalls{
			{
				Path: "/bin/test",
				Args: []string{"test"},
			},
		},
	})
	objCache.SetApplicationProfile(profile)

	// Set up network neighborhood
	nn := &v1beta1.NetworkNeighborhood{}
	nn.Spec.Containers = append(nn.Spec.Containers, v1beta1.NetworkNeighborhoodContainer{
		Name: "test-container",
		Egress: []v1beta1.NetworkNeighbor{
			{
				Identifier: "test-connection",
				Type:       "external",
				DNSNames:   []string{"test.example.com"},
			},
		},
	})
	objCache.SetNetworkNeighborhood(nn)

	registry := NewProfileRegistry(objCache).(*ProfileRegistryImpl)

	appProfile, nnProfile, found := registry.GetAvailableProfiles("test-container", "container-123")

	assert.True(t, found)
	assert.NotNil(t, appProfile)
	assert.NotNil(t, nnProfile)
	assert.Equal(t, "test-container", appProfile.Name)
	assert.Equal(t, "test-container", nnProfile.Name)
	assert.Len(t, appProfile.Execs, 1)
	assert.Equal(t, "/bin/test", appProfile.Execs[0].Path)
	assert.Len(t, nnProfile.Egress, 1)
	assert.Equal(t, "test-connection", nnProfile.Egress[0].Identifier)
}

func TestGetAvailableProfiles_NoApplicationProfile(t *testing.T) {
	objCache := &RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}

	// Set up network neighborhood only
	nn := &v1beta1.NetworkNeighborhood{}
	nn.Spec.Containers = append(nn.Spec.Containers, v1beta1.NetworkNeighborhoodContainer{
		Name: "test-container",
	})
	objCache.SetNetworkNeighborhood(nn)

	registry := NewProfileRegistry(objCache).(*ProfileRegistryImpl)

	appProfile, nnProfile, found := registry.GetAvailableProfiles("test-container", "container-123")

	assert.False(t, found)
	assert.Nil(t, appProfile)
	assert.Nil(t, nnProfile)
}

func TestGetAvailableProfiles_NoNetworkNeighborhood(t *testing.T) {
	objCache := &RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}

	// Set up application profile only
	profile := &v1beta1.ApplicationProfile{}
	profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
		Name: "test-container",
	})
	objCache.SetApplicationProfile(profile)

	registry := NewProfileRegistry(objCache).(*ProfileRegistryImpl)

	appProfile, nnProfile, found := registry.GetAvailableProfiles("test-container", "container-123")

	assert.False(t, found)
	assert.Nil(t, appProfile)
	assert.Nil(t, nnProfile)
}

func TestGetAvailableProfiles_ContainerNotFoundInAppProfile(t *testing.T) {
	objCache := &RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}

	// Set up application profile with different container name
	profile := &v1beta1.ApplicationProfile{}
	profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
		Name: "other-container",
	})
	objCache.SetApplicationProfile(profile)

	// Set up network neighborhood
	nn := &v1beta1.NetworkNeighborhood{}
	nn.Spec.Containers = append(nn.Spec.Containers, v1beta1.NetworkNeighborhoodContainer{
		Name: "test-container",
	})
	objCache.SetNetworkNeighborhood(nn)

	registry := NewProfileRegistry(objCache).(*ProfileRegistryImpl)

	appProfile, nnProfile, found := registry.GetAvailableProfiles("test-container", "container-123")

	assert.False(t, found)
	assert.Nil(t, appProfile)
	assert.Nil(t, nnProfile)
}

func TestGetAvailableProfiles_ContainerNotFoundInNetworkNeighborhood(t *testing.T) {
	objCache := &RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}

	// Set up application profile
	profile := &v1beta1.ApplicationProfile{}
	profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
		Name: "test-container",
	})
	objCache.SetApplicationProfile(profile)

	// Set up network neighborhood with different container name
	nn := &v1beta1.NetworkNeighborhood{}
	nn.Spec.Containers = append(nn.Spec.Containers, v1beta1.NetworkNeighborhoodContainer{
		Name: "other-container",
	})
	objCache.SetNetworkNeighborhood(nn)

	registry := NewProfileRegistry(objCache).(*ProfileRegistryImpl)

	appProfile, nnProfile, found := registry.GetAvailableProfiles("test-container", "container-123")

	assert.False(t, found)
	assert.Nil(t, appProfile)
	assert.Nil(t, nnProfile)
}

func TestGetAvailableProfiles_EmptyProfiles(t *testing.T) {
	objCache := &RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}

	// Set up empty application profile
	profile := &v1beta1.ApplicationProfile{}
	objCache.SetApplicationProfile(profile)

	// Set up empty network neighborhood
	nn := &v1beta1.NetworkNeighborhood{}
	objCache.SetNetworkNeighborhood(nn)

	registry := NewProfileRegistry(objCache).(*ProfileRegistryImpl)

	appProfile, nnProfile, found := registry.GetAvailableProfiles("test-container", "container-123")

	assert.False(t, found)
	assert.Nil(t, appProfile)
	assert.Nil(t, nnProfile)
}

func TestGetAvailableProfiles_MultipleContainers(t *testing.T) {
	objCache := &RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}

	// Set up application profile with multiple containers
	profile := &v1beta1.ApplicationProfile{}
	profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
		Name: "container1",
		Execs: []v1beta1.ExecCalls{
			{Path: "/bin/app1"},
		},
	})
	profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
		Name: "container2",
		Execs: []v1beta1.ExecCalls{
			{Path: "/bin/app2"},
		},
	})
	objCache.SetApplicationProfile(profile)

	// Set up network neighborhood with multiple containers
	nn := &v1beta1.NetworkNeighborhood{}
	nn.Spec.Containers = append(nn.Spec.Containers, v1beta1.NetworkNeighborhoodContainer{
		Name: "container1",
		Egress: []v1beta1.NetworkNeighbor{
			{Identifier: "conn1", DNSNames: []string{"example1.com"}},
		},
	})
	nn.Spec.Containers = append(nn.Spec.Containers, v1beta1.NetworkNeighborhoodContainer{
		Name: "container2",
		Egress: []v1beta1.NetworkNeighbor{
			{Identifier: "conn2", DNSNames: []string{"example2.com"}},
		},
	})
	objCache.SetNetworkNeighborhood(nn)

	registry := NewProfileRegistry(objCache).(*ProfileRegistryImpl)

	// Test first container
	appProfile1, nnProfile1, found1 := registry.GetAvailableProfiles("container1", "container-123")
	assert.True(t, found1)
	assert.Equal(t, "container1", appProfile1.Name)
	assert.Equal(t, "container1", nnProfile1.Name)
	assert.Equal(t, "/bin/app1", appProfile1.Execs[0].Path)
	assert.Equal(t, "conn1", nnProfile1.Egress[0].Identifier)

	// Test second container
	appProfile2, nnProfile2, found2 := registry.GetAvailableProfiles("container2", "container-123")
	assert.True(t, found2)
	assert.Equal(t, "container2", appProfile2.Name)
	assert.Equal(t, "container2", nnProfile2.Name)
	assert.Equal(t, "/bin/app2", appProfile2.Execs[0].Path)
	assert.Equal(t, "conn2", nnProfile2.Egress[0].Identifier)
}

func TestGetAvailableProfiles_ComplexData(t *testing.T) {
	objCache := &RuleObjectCacheMock{
		ContainerIDToSharedData: maps.NewSafeMap[string, *objectcache.WatchedContainerData](),
	}

	// Set up complex application profile
	profile := &v1beta1.ApplicationProfile{}
	profile.Spec.Containers = append(profile.Spec.Containers, v1beta1.ApplicationProfileContainer{
		Name: "web-server",
		Execs: []v1beta1.ExecCalls{
			{
				Path: "/usr/bin/nginx",
				Args: []string{"-g", "daemon off;"},
			},
			{
				Path: "/bin/bash",
				Args: []string{"-c", "echo 'hello'"},
			},
		},
		Opens: []v1beta1.OpenCalls{
			{
				Path:  "/etc/nginx/nginx.conf",
				Flags: []string{"O_RDONLY"},
			},
		},
	})
	objCache.SetApplicationProfile(profile)

	// Set up complex network neighborhood
	nn := &v1beta1.NetworkNeighborhood{}
	nn.Spec.Containers = append(nn.Spec.Containers, v1beta1.NetworkNeighborhoodContainer{
		Name: "web-server",
		Egress: []v1beta1.NetworkNeighbor{
			{
				Identifier: "http-connection",
				Type:       "external",
				DNSNames:   []string{"api.example.com"},
				Ports: []v1beta1.NetworkPort{
					{
						Name:     "HTTP",
						Protocol: "TCP",
						Port:     ptr.To(int32(80)),
					},
				},
			},
			{
				Identifier: "https-connection",
				Type:       "external",
				DNSNames:   []string{"secure.example.com"},
				Ports: []v1beta1.NetworkPort{
					{
						Name:     "HTTPS",
						Protocol: "TCP",
						Port:     ptr.To(int32(443)),
					},
				},
			},
		},
	})
	objCache.SetNetworkNeighborhood(nn)

	registry := NewProfileRegistry(objCache).(*ProfileRegistryImpl)

	appProfile, nnProfile, found := registry.GetAvailableProfiles("web-server", "container-123")

	assert.True(t, found)
	assert.NotNil(t, appProfile)
	assert.NotNil(t, nnProfile)
	assert.Equal(t, "web-server", appProfile.Name)
	assert.Equal(t, "web-server", nnProfile.Name)

	// Verify application profile data
	assert.Len(t, appProfile.Execs, 2)
	assert.Equal(t, "/usr/bin/nginx", appProfile.Execs[0].Path)
	assert.Equal(t, []string{"-g", "daemon off;"}, appProfile.Execs[0].Args)
	assert.Equal(t, "/bin/bash", appProfile.Execs[1].Path)
	assert.Equal(t, []string{"-c", "echo 'hello'"}, appProfile.Execs[1].Args)

	assert.Len(t, appProfile.Opens, 1)
	assert.Equal(t, "/etc/nginx/nginx.conf", appProfile.Opens[0].Path)
	assert.Equal(t, []string{"O_RDONLY"}, appProfile.Opens[0].Flags)

	// Verify network neighborhood data
	assert.Len(t, nnProfile.Egress, 2)
	assert.Equal(t, "http-connection", nnProfile.Egress[0].Identifier)
	assert.Equal(t, "api.example.com", nnProfile.Egress[0].DNSNames[0])
	assert.Equal(t, v1beta1.Protocol("TCP"), nnProfile.Egress[0].Ports[0].Protocol)
	assert.Equal(t, int32(80), *nnProfile.Egress[0].Ports[0].Port)
	assert.Equal(t, "https-connection", nnProfile.Egress[1].Identifier)
	assert.Equal(t, "secure.example.com", nnProfile.Egress[1].DNSNames[0])
	assert.Equal(t, v1beta1.Protocol("TCP"), nnProfile.Egress[1].Ports[0].Protocol)
	assert.Equal(t, int32(443), *nnProfile.Egress[1].Ports[0].Port)
}
