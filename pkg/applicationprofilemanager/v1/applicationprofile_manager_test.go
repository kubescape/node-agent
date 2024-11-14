package applicationprofilemanager

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/config"
	tracerhttptype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/seccompmanager"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
	"github.com/stretchr/testify/assert"
	istiocache "istio.io/pkg/cache"
)

func TestApplicationProfileManager(t *testing.T) {
	cfg := config.Config{
		InitialDelay:     1 * time.Second,
		MaxSniffingTime:  5 * time.Minute,
		UpdateDataPeriod: 5 * time.Second,
	}
	ctx := context.TODO()
	k8sClient := &k8sclient.K8sClientMock{}
	storageClient := &storage.StorageHttpClientMock{}
	k8sObjectCacheMock := &objectcache.K8sObjectCacheMock{}
	seccompManagerMock := &seccompmanager.SeccompManagerMock{}
	am, err := CreateApplicationProfileManager(ctx, cfg, "cluster", k8sClient, storageClient, mapset.NewSet[string](), k8sObjectCacheMock, seccompManagerMock)
	assert.NoError(t, err)
	// prepare container
	container := &containercollection.Container{
		K8s: containercollection.K8sMetadata{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace:     "ns",
				PodName:       "pod",
				ContainerName: "cont",
			},
		},
		Runtime: containercollection.RuntimeMetadata{
			BasicRuntimeMetadata: types.BasicRuntimeMetadata{
				ContainerID: "5fff6a395ce4e6984a9447cc6cfb09f473eaf278498243963fcc944889bc8400",
			},
		},
	}
	// register peek function for syscall tracer
	go am.RegisterPeekFunc(func(_ uint64) ([]string, error) {
		return []string{"dup", "listen"}, nil
	})
	// report capability
	go am.ReportCapability("ns/pod/cont", "NET_BIND_SERVICE")
	// report file exec
	go am.ReportFileExec("ns/pod/cont", "", []string{"ls"}) // will not be reported
	go am.ReportFileExec("ns/pod/cont", "/bin/bash", []string{"-c", "ls"})
	go am.ReportFileExec("ns/pod/cont", "/bin/bash", []string{"-c", "ls"})       // duplicate - not reported
	go am.ReportFileExec("ns/pod/cont", "/bin/bash", []string{"-c", "ls", "-l"}) // additional arg - reported
	go am.ReportFileExec("ns/pod/cont", "/bin/bash", []string{"ls", "-c"})       // different order of args - reported
	go am.ReportFileExec("ns/pod/cont", "/bin/ls", []string{"-l"})
	// report file open
	go am.ReportFileOpen("ns/pod/cont", "/etc/passwd", []string{"O_RDONLY"})
	// report container started (race condition with reports)
	am.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: container,
	})
	// let it run for a while
	time.Sleep(15 * time.Second) // need to sleep longer because of AddRandomDuration in startApplicationProfiling
	// report another file open
	go am.ReportFileOpen("ns/pod/cont", "/etc/hosts", []string{"O_RDONLY"})
	// report another file open
	go am.ReportFileExec("ns/pod/cont", "/bin/bash", []string{"-c", "ls"}) // duplicate - will not be reported

	// report endpoint

	parsedURL, _ := url.Parse("/abc")

	request := &http.Request{
		Method: "GET",
		URL:    parsedURL,
		Host:   "localhost:123 GMT",

		Header: map[string][]string{},
	}

	testEvent := &tracerhttptype.Event{
		Request:  request,
		Internal: false,

		Direction: "inbound",
	}

	go am.ReportHTTPEvent("ns/pod/cont", testEvent)

	request = &http.Request{
		Method: "GET",
		URL:    parsedURL,
		Host:   "localhost",

		Header: map[string][]string{},
	}

	testEvent = &tracerhttptype.Event{
		Request:  request,
		Internal: false,

		Direction: "inbound",
	}

	go am.ReportHTTPEvent("ns/pod/cont", testEvent)

	request = &http.Request{
		Method: "POST",
		Host:   "localhost",

		URL: parsedURL,
		Header: map[string][]string{
			"Connection": {"keep-alive"},
		},
	}

	testEvent = &tracerhttptype.Event{
		Request:   request,
		Internal:  false,
		Direction: "inbound",
	}

	go am.ReportHTTPEvent("ns/pod/cont", testEvent)

	request = &http.Request{
		Method: "POST",
		URL:    parsedURL,
		Host:   "localhost",
		Header: map[string][]string{
			"Connection": {"keep-alive"},
		},
	}

	testEvent = &tracerhttptype.Event{
		Request:   request,
		Internal:  false,
		Direction: "inbound",
	}

	go am.ReportHTTPEvent("ns/pod/cont", testEvent)

	request = &http.Request{
		Method: "POST",
		URL:    parsedURL,
		Host:   "localhost:123",
		Header: map[string][]string{
			"Connection": {"keep-alive"},
		},
	}

	testEvent = &tracerhttptype.Event{
		Request:   request,
		Internal:  false,
		Direction: "inbound",
	}

	go am.ReportHTTPEvent("ns/pod/cont", testEvent)

	time.Sleep(8 * time.Second)

	// sleep more
	time.Sleep(2 * time.Second)
	// report container stopped
	am.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeRemoveContainer,
		Container: container,
	})
	// let it stop
	time.Sleep(2 * time.Second)
	// verify generated CRDs
	assert.Equal(t, 2, len(storageClient.ApplicationProfiles))
	// check the first profile
	sort.Strings(storageClient.ApplicationProfiles[0].Spec.Containers[0].Capabilities)
	assert.Equal(t, []string{"dup", "listen"}, storageClient.ApplicationProfiles[0].Spec.Containers[1].Syscalls)
	assert.Equal(t, []string{"NET_BIND_SERVICE"}, storageClient.ApplicationProfiles[0].Spec.Containers[1].Capabilities)

	reportedExecs := storageClient.ApplicationProfiles[0].Spec.Containers[1].Execs
	expectedExecs := []v1beta1.ExecCalls{
		{Path: "/bin/bash", Args: []string{"-c", "ls"}, Envs: []string(nil)},
		{Path: "/bin/bash", Args: []string{"-c", "ls", "-l"}, Envs: []string(nil)},
		{Path: "/bin/bash", Args: []string{"ls", "-c"}, Envs: []string(nil)},
		{Path: "/bin/ls", Args: []string{"-l"}, Envs: []string(nil)},
	}
	assert.Len(t, reportedExecs, len(expectedExecs))
	for _, expectedExec := range expectedExecs {
		assert.Contains(t, reportedExecs, expectedExec)
	}
	assert.Equal(t, []v1beta1.OpenCalls{{Path: "/etc/passwd", Flags: []string{"O_RDONLY"}}}, storageClient.ApplicationProfiles[0].Spec.Containers[1].Opens)

	expectedEndpoints := GetExcpectedEndpoints(t)
	actualEndpoints := storageClient.ApplicationProfiles[1].Spec.Containers[1].Endpoints

	sortHTTPEndpoints(expectedEndpoints)
	sortHTTPEndpoints(actualEndpoints)

	assert.Equal(t, expectedEndpoints, actualEndpoints)
	// check the second profile - this is a patch for execs and opens
	sort.Strings(storageClient.ApplicationProfiles[1].Spec.Containers[0].Capabilities)
	assert.Equal(t, []string{"NET_BIND_SERVICE"}, storageClient.ApplicationProfiles[1].Spec.Containers[1].Capabilities)
	assert.Equal(t, storageClient.ApplicationProfiles[0].Spec.Containers[1].Execs, storageClient.ApplicationProfiles[1].Spec.Containers[1].Execs)
	assert.Equal(t, []v1beta1.OpenCalls{
		{Path: "/etc/passwd", Flags: []string{"O_RDONLY"}},
		{Path: "/etc/hosts", Flags: []string{"O_RDONLY"}},
	}, storageClient.ApplicationProfiles[1].Spec.Containers[1].Opens)
}

func GetExcpectedEndpoints(t *testing.T) []v1beta1.HTTPEndpoint {
	headers := map[string][]string{"Host": {"localhost"}, "Connection": {"keep-alive"}}
	rawJSON, err := json.Marshal(headers)
	assert.NoError(t, err)

	endpointPost := v1beta1.HTTPEndpoint{
		Endpoint:  ":80/abc",
		Methods:   []string{"POST"},
		Internal:  false,
		Direction: "inbound",
		Headers:   rawJSON}

	headers = map[string][]string{"Host": {"localhost"}}
	rawJSON, err = json.Marshal(headers)
	assert.NoError(t, err)

	endpointGet := v1beta1.HTTPEndpoint{
		Endpoint:  ":80/abc",
		Methods:   []string{"GET"},
		Internal:  false,
		Direction: "inbound",
		Headers:   rawJSON}

	headers = map[string][]string{"Host": {"localhost:123"}, "Connection": {"keep-alive"}}
	rawJSON, err = json.Marshal(headers)
	assert.NoError(t, err)

	endpointPort := v1beta1.HTTPEndpoint{
		Endpoint:  ":123/abc",
		Methods:   []string{"POST"},
		Internal:  false,
		Direction: "inbound",
		Headers:   rawJSON}

	return []v1beta1.HTTPEndpoint{endpointPost, endpointGet, endpointPort}
}

func sortHTTPEndpoints(endpoints []v1beta1.HTTPEndpoint) {
	sort.Slice(endpoints, func(i, j int) bool {
		// Sort by Endpoint first
		if endpoints[i].Endpoint != endpoints[j].Endpoint {
			return endpoints[i].Endpoint < endpoints[j].Endpoint
		}
		// If Endpoints are the same, sort by the first Method
		if len(endpoints[i].Methods) > 0 && len(endpoints[j].Methods) > 0 {
			return endpoints[i].Methods[0] < endpoints[j].Methods[0]
		}
		// If Methods are empty or the same, sort by Internal
		if endpoints[i].Internal != endpoints[j].Internal {
			return endpoints[i].Internal
		}
		// If Internal is the same, sort by Direction
		if endpoints[i].Direction != endpoints[j].Direction {
			return string(endpoints[i].Direction) < string(endpoints[j].Direction)
		}
		// If all else is equal, sort by Headers
		return string(endpoints[i].Headers) < string(endpoints[j].Headers)
	})
}

func BenchmarkReportFileOpen(b *testing.B) {
	savedOpens := maps.SafeMap[string, mapset.Set[string]]{}
	savedOpens.Set("/proc/"+dynamicpathdetector.DynamicIdentifier+"/foo/bar", mapset.NewSet("O_LARGEFILE", "O_RDONLY"))
	paths := []string{"/proc/12345/foo/bar", "/bin/ls", "/etc/passwd"}
	flags := []string{"O_CLOEXEC", "O_RDONLY"}
	for i := 0; i < b.N; i++ {
		for _, path := range paths {
			if strings.HasPrefix(path, "/proc/") {
				path = procRegex.ReplaceAllString(path, "/proc/"+dynamicpathdetector.DynamicIdentifier)
			}
			if savedOpens.Has(path) && savedOpens.Get(path).Contains(flags...) {
				continue
			}
		}
	}
	b.ReportAllocs()
}

func TestReportRulePolicy(t *testing.T) {
	// Setup common test environment
	cfg := config.Config{
		InitialDelay:     1 * time.Second,
		MaxSniffingTime:  5 * time.Minute,
		UpdateDataPeriod: 1 * time.Second,
	}
	ctx := context.TODO()
	k8sClient := &k8sclient.K8sClientMock{}
	storageClient := &storage.StorageHttpClientMock{}
	k8sObjectCacheMock := &objectcache.K8sObjectCacheMock{}
	seccompManagerMock := &seccompmanager.SeccompManagerMock{}

	tests := []struct {
		name             string
		k8sContainerID   string
		ruleID           string
		allowedProcess   string
		allowedContainer bool
		existingSaved    *v1beta1.RulePolicy
		existingToSave   *v1beta1.RulePolicy
		expectedPolicy   *v1beta1.RulePolicy
		shouldSet        bool
	}{
		{
			name:             "New policy with process",
			k8sContainerID:   "ns/pod/cont",
			ruleID:           "rule1",
			allowedProcess:   "process1",
			allowedContainer: false,
			existingSaved:    nil,
			existingToSave:   nil,
			expectedPolicy: &v1beta1.RulePolicy{
				AllowedContainer: false,
				AllowedProcesses: []string{"process1"},
			},
			shouldSet: true,
		},
		{
			name:             "New policy with container allowed",
			k8sContainerID:   "ns/pod/cont",
			ruleID:           "rule2",
			allowedProcess:   "",
			allowedContainer: true,
			existingSaved:    nil,
			existingToSave:   nil,
			expectedPolicy: &v1beta1.RulePolicy{
				AllowedContainer: true,
				AllowedProcesses: []string{""},
			},
			shouldSet: true,
		},
		{
			name:             "Merge with existing toBeSaved policy - new process",
			k8sContainerID:   "ns/pod/cont",
			ruleID:           "rule3",
			allowedProcess:   "process2",
			allowedContainer: false,
			existingToSave: &v1beta1.RulePolicy{
				AllowedContainer: false,
				AllowedProcesses: []string{"process1"},
			},
			expectedPolicy: &v1beta1.RulePolicy{
				AllowedContainer: false,
				AllowedProcesses: []string{"process1", "process2"},
			},
			shouldSet: true,
		},
		{
			name:             "Merge with existing toBeSaved policy - enable container",
			k8sContainerID:   "ns/pod/cont",
			ruleID:           "rule4",
			allowedProcess:   "",
			allowedContainer: true,
			existingToSave: &v1beta1.RulePolicy{
				AllowedContainer: false,
				AllowedProcesses: []string{"process1"},
			},
			expectedPolicy: &v1beta1.RulePolicy{
				AllowedContainer: true,
				AllowedProcesses: []string{"process1"},
			},
			shouldSet: true,
		},
		{
			name:             "Skip if policy already in saved",
			k8sContainerID:   "ns/pod/cont",
			ruleID:           "rule5",
			allowedProcess:   "process1",
			allowedContainer: false,
			existingSaved: &v1beta1.RulePolicy{
				AllowedContainer: false,
				AllowedProcesses: []string{"process1"},
			},
			shouldSet: false,
		},
		{
			name:             "Skip if policy already in toBeSaved",
			k8sContainerID:   "ns/pod/cont",
			ruleID:           "rule6",
			allowedProcess:   "process1",
			allowedContainer: false,
			existingToSave: &v1beta1.RulePolicy{
				AllowedContainer: false,
				AllowedProcesses: []string{"process1"},
			},
			shouldSet: false,
		},
		{
			name:             "Deduplicate processes",
			k8sContainerID:   "ns/pod/cont",
			ruleID:           "rule7",
			allowedProcess:   "process1",
			allowedContainer: false,
			existingToSave: &v1beta1.RulePolicy{
				AllowedContainer: false,
				AllowedProcesses: []string{"process1", "process2"},
			},
			expectedPolicy: &v1beta1.RulePolicy{
				AllowedContainer: false,
				AllowedProcesses: []string{"process1", "process2"},
			},
			shouldSet: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			am, err := CreateApplicationProfileManager(ctx, cfg, "cluster", k8sClient, storageClient, mapset.NewSet[string](), k8sObjectCacheMock, seccompManagerMock)
			assert.NoError(t, err)

			am.savedRulePolicies.Set(tt.k8sContainerID, istiocache.NewTTL(5*am.cfg.UpdateDataPeriod, am.cfg.UpdateDataPeriod))
			am.toSaveRulePolicies.Set(tt.k8sContainerID, new(maps.SafeMap[string, *v1beta1.RulePolicy]))
			am.trackedContainers.Add(tt.k8sContainerID)

			if tt.existingSaved != nil {
				am.savedRulePolicies.Get(tt.k8sContainerID).Set(tt.ruleID, tt.existingSaved)
			}
			if tt.existingToSave != nil {
				am.toSaveRulePolicies.Get(tt.k8sContainerID).Set(tt.ruleID, tt.existingToSave)
			}

			am.ReportRulePolicy(tt.k8sContainerID, tt.ruleID, tt.allowedProcess, tt.allowedContainer)

			if tt.shouldSet {
				resultPolicy := am.toSaveRulePolicies.Get(tt.k8sContainerID).Get(tt.ruleID)
				assert.NotNil(t, resultPolicy)
				assert.Equal(t, tt.expectedPolicy.AllowedContainer, resultPolicy.AllowedContainer)
				assert.ElementsMatch(t, tt.expectedPolicy.AllowedProcesses, resultPolicy.AllowedProcesses)
			} else {
				resultPolicy := am.toSaveRulePolicies.Get(tt.k8sContainerID).Get(tt.ruleID)
				if tt.existingToSave != nil {
					assert.Equal(t, tt.existingToSave.AllowedContainer, resultPolicy.AllowedContainer)
					assert.ElementsMatch(t, tt.existingToSave.AllowedProcesses, resultPolicy.AllowedProcesses)
				} else {
					assert.Nil(t, resultPolicy)
				}
			}
		})
	}
}
