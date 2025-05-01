package applicationprofilemanager

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/armosec/utils-k8s-go/wlid"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	tracerhttptype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/objectcache"
	rulebindingcachev1 "github.com/kubescape/node-agent/pkg/rulebindingmanager/cache"
	"github.com/kubescape/node-agent/pkg/seccompmanager"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
	"github.com/stretchr/testify/assert"
	istiocache "istio.io/pkg/cache"
)

func ensureInstanceID(container *containercollection.Container, watchedContainer *utils.WatchedContainerData, k8sclient *k8sclient.K8sClientMock, clusterName string) error {
	if watchedContainer.InstanceID != nil {
		return nil
	}
	wl, err := k8sclient.GetWorkload(container.K8s.Namespace, "Pod", container.K8s.PodName)
	if err != nil {
		return fmt.Errorf("failed to get workload: %w", err)
	}
	pod := wl.(*workloadinterface.Workload)
	// fill container type, index and names
	if watchedContainer.ContainerType == utils.Unknown {
		if err := watchedContainer.SetContainerInfo(pod, container.K8s.ContainerName); err != nil {
			return fmt.Errorf("failed to set container info: %w", err)
		}
	}
	// find parentWlid
	kind, name, err := k8sclient.CalculateWorkloadParentRecursive(pod)
	if err != nil {
		return fmt.Errorf("failed to calculate workload parent: %w", err)
	}
	parentWorkload, err := k8sclient.GetWorkload(pod.GetNamespace(), kind, name)
	if err != nil {
		return fmt.Errorf("failed to get parent workload: %w", err)
	}
	w := parentWorkload.(*workloadinterface.Workload)
	watchedContainer.Wlid = w.GenerateWlid(clusterName)
	err = wlid.IsWlidValid(watchedContainer.Wlid)
	if err != nil {
		return fmt.Errorf("failed to validate WLID: %w", err)
	}
	watchedContainer.ParentResourceVersion = w.GetResourceVersion()
	// find instanceID - this has to be the last one
	instanceIDs, err := instanceidhandler.GenerateInstanceID(pod)
	if err != nil {
		return fmt.Errorf("failed to generate instanceID: %w", err)
	}
	for i := range instanceIDs {
		if instanceIDs[i].GetContainerName() == container.K8s.ContainerName {
			watchedContainer.InstanceID = instanceIDs[i]
		}
	}
	if watchedContainer.InstanceID == nil {
		return fmt.Errorf("failed to find instance id for container %s", container.K8s.ContainerName)
	}
	return nil
}

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
	ruleBindingCache := rulebindingcachev1.NewCacheMock("node1")
	am, err := CreateApplicationProfileManager(ctx, cfg, "cluster", k8sClient, storageClient, k8sObjectCacheMock, seccompManagerMock, nil, ruleBindingCache)
	assert.NoError(t, err)
	// prepare container
	container := &containercollection.Container{
		K8s: containercollection.K8sMetadata{
			BasicK8sMetadata: eventtypes.BasicK8sMetadata{
				Namespace:     "ns",
				PodName:       "pod",
				ContainerName: "cont",
			},
		},
		Runtime: containercollection.RuntimeMetadata{
			BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
				ContainerID:        "5fff6a395ce4e6984a9447cc6cfb09f473eaf278498243963fcc944889bc8400",
				ContainerStartedAt: eventtypes.Time(time.Now().UnixNano()),
			},
		},
	}
	sharedWatchedContainerData := &utils.WatchedContainerData{}
	err = ensureInstanceID(container, sharedWatchedContainerData, k8sClient, "cluster")
	assert.NoError(t, err)
	k8sObjectCacheMock.SetSharedContainerData(container.Runtime.ContainerID, sharedWatchedContainerData)
	// register peek function for syscall tracer
	go am.RegisterPeekFunc(func(_ uint64) ([]string, error) {
		return []string{"dup", "listen"}, nil
	})
	// report capability
	go am.ReportCapability("ns/pod/cont", "NET_BIND_SERVICE")
	// report file exec
	e := &events.ExecEvent{
		Event: tracerexectype.Event{
			Event: eventtypes.Event{
				CommonData: eventtypes.CommonData{
					K8s: eventtypes.K8sMetadata{
						BasicK8sMetadata: eventtypes.BasicK8sMetadata{
							ContainerName: "cont",
						},
					},
				},
			},
			Comm: "/bin/bash",
			Args: []string{"/bin/bash", "-c", "ls"},
		},
	}
	go am.ReportFileExec("ns/pod/cont", *e)
	go am.ReportFileExec("ns/pod/cont", *e) // duplicate - not reported
	e.Args = []string{"/bin/bash", "-c", "ls", "-l"}
	go am.ReportFileExec("ns/pod/cont", *e) // additional arg - reported
	e.Args = []string{"/bin/bash", "ls", "-c"}
	go am.ReportFileExec("ns/pod/cont", *e) // different order of args - reported
	e.Args = []string{"/bin/ls", "-l"}
	go am.ReportFileExec("ns/pod/cont", *e)
	// report file open
	f := &events.OpenEvent{
		Event: traceropentype.Event{
			Event: eventtypes.Event{
				CommonData: eventtypes.CommonData{
					K8s: eventtypes.K8sMetadata{
						BasicK8sMetadata: eventtypes.BasicK8sMetadata{
							ContainerName: "cont",
						},
					},
				},
			},
			Path:     "/etc/passwd",
			FullPath: "/etc/passwd",
			Flags:    []string{"O_RDONLY"},
		},
	}
	go am.ReportFileOpen("ns/pod/cont", *f)

	// report container started (race condition with reports)
	am.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: container,
	})
	// let it run for a while
	time.Sleep(15 * time.Second) // need to sleep longer because of AddRandomDuration in startApplicationProfiling
	// report another file open
	f.Path = "/etc/hosts"
	f.FullPath = "/etc/hosts"
	go am.ReportFileOpen("ns/pod/cont", *f)
	// report another file open
	e.Args = []string{"/bin/bash", "-c", "ls"}
	go am.ReportFileExec("ns/pod/cont", *e) // duplicate - will not be reported

	// report endpoint

	parsedURL, _ := url.Parse("/abc")

	request := &http.Request{
		Method: "GET",
		URL:    parsedURL,
		Host:   "localhost:123 GMT",

		Header: map[string][]string{},
	}

	response := &http.Response{
		StatusCode: 200,
		Header:     map[string][]string{},
	}

	testEvent := &tracerhttptype.Event{
		Request:  request,
		Response: response,
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
		Response: response,
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
		Response:  response,
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
		Response:  response,
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
		Response:  response,
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
		{Path: "/bin/bash", Args: []string{"/bin/bash", "-c", "ls"}, Envs: []string(nil)},
		{Path: "/bin/bash", Args: []string{"/bin/bash", "-c", "ls", "-l"}, Envs: []string(nil)},
		{Path: "/bin/bash", Args: []string{"/bin/bash", "ls", "-c"}, Envs: []string(nil)},
		{Path: "/bin/ls", Args: []string{"/bin/ls", "-l"}, Envs: []string(nil)},
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
			ruleBindingCache := rulebindingcachev1.NewCacheMock("node1")
			am, err := CreateApplicationProfileManager(ctx, cfg, "cluster", k8sClient, storageClient, k8sObjectCacheMock, seccompManagerMock, nil, ruleBindingCache)
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

func TestReportIdentifiedCallStack(t *testing.T) {
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
		name           string
		k8sContainerID string
		callStacks     []v1beta1.IdentifiedCallStack
		expected       []v1beta1.IdentifiedCallStack
	}{
		{
			name:           "Single callstack",
			k8sContainerID: "ns/pod/cont",
			callStacks: []v1beta1.IdentifiedCallStack{
				{
					CallID: "open",
					CallStack: v1beta1.CallStack{
						Root: v1beta1.CallStackNode{
							Frame: v1beta1.StackFrame{
								FileID: "1",
								Lineno: "42",
							},
							Children: []v1beta1.CallStackNode{},
						},
					},
				},
			},
			expected: []v1beta1.IdentifiedCallStack{
				{
					CallID: "open",
					CallStack: v1beta1.CallStack{
						Root: v1beta1.CallStackNode{
							Frame: v1beta1.StackFrame{
								FileID: "1",
								Lineno: "42",
							},
							Children: []v1beta1.CallStackNode{},
						},
					},
				},
			},
		},
		{
			name:           "Multiple callstacks",
			k8sContainerID: "ns/pod/cont",
			callStacks: []v1beta1.IdentifiedCallStack{
				{
					CallID: "open",
					CallStack: v1beta1.CallStack{
						Root: v1beta1.CallStackNode{
							Frame: v1beta1.StackFrame{
								FileID: "1",
								Lineno: "42",
							},
							Children: []v1beta1.CallStackNode{
								{
									Frame: v1beta1.StackFrame{
										FileID: "2",
										Lineno: "84",
									},
									Children: []v1beta1.CallStackNode{},
								},
							},
						},
					},
				},
				{
					CallID: "exec",
					CallStack: v1beta1.CallStack{
						Root: v1beta1.CallStackNode{
							Frame: v1beta1.StackFrame{
								FileID: "3",
								Lineno: "120",
							},
							Children: []v1beta1.CallStackNode{},
						},
					},
				},
			},
			expected: []v1beta1.IdentifiedCallStack{
				{
					CallID: "open",
					CallStack: v1beta1.CallStack{
						Root: v1beta1.CallStackNode{
							Frame: v1beta1.StackFrame{
								FileID: "1",
								Lineno: "42",
							},
							Children: []v1beta1.CallStackNode{
								{
									Frame: v1beta1.StackFrame{
										FileID: "2",
										Lineno: "84",
									},
									Children: []v1beta1.CallStackNode{},
								},
							},
						},
					},
				},
				{
					CallID: "exec",
					CallStack: v1beta1.CallStack{
						Root: v1beta1.CallStackNode{
							Frame: v1beta1.StackFrame{
								FileID: "3",
								Lineno: "120",
							},
							Children: []v1beta1.CallStackNode{},
						},
					},
				},
			},
		},
		{
			name:           "Duplicate callstack",
			k8sContainerID: "ns/pod/cont",
			callStacks: []v1beta1.IdentifiedCallStack{
				{
					CallID: "open",
					CallStack: v1beta1.CallStack{
						Root: v1beta1.CallStackNode{
							Frame: v1beta1.StackFrame{
								FileID: "1",
								Lineno: "42",
							},
							Children: []v1beta1.CallStackNode{},
						},
					},
				},
				{
					CallID: "open",
					CallStack: v1beta1.CallStack{
						Root: v1beta1.CallStackNode{
							Frame: v1beta1.StackFrame{
								FileID: "1",
								Lineno: "42",
							},
							Children: []v1beta1.CallStackNode{},
						},
					},
				},
			},
			expected: []v1beta1.IdentifiedCallStack{
				{
					CallID: "open",
					CallStack: v1beta1.CallStack{
						Root: v1beta1.CallStackNode{
							Frame: v1beta1.StackFrame{
								FileID: "1",
								Lineno: "42",
							},
							Children: []v1beta1.CallStackNode{},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleBindingCache := rulebindingcachev1.NewCacheMock("node1")
			am, err := CreateApplicationProfileManager(ctx, cfg, "cluster", k8sClient, storageClient, k8sObjectCacheMock, seccompManagerMock, nil, ruleBindingCache)
			if err != nil {
				t.Fatalf("Failed to create ApplicationProfileManager: %v", err)
			}

			// Initialize container tracking
			am.savedCallStacks.Set(tt.k8sContainerID, istiocache.NewTTL(5*am.cfg.UpdateDataPeriod, am.cfg.UpdateDataPeriod))
			am.toSaveCallStacks.Set(tt.k8sContainerID, new(maps.SafeMap[string, *v1beta1.IdentifiedCallStack]))
			am.trackedContainers.Add(tt.k8sContainerID)

			// Report each callstack
			for _, callStack := range tt.callStacks {
				am.ReportIdentifiedCallStack(tt.k8sContainerID, &callStack)
			}

			// Collect all callstacks that were queued to be saved
			var resultCallStacks []v1beta1.IdentifiedCallStack
			am.toSaveCallStacks.Get(tt.k8sContainerID).Range(func(identifier string, callStack *v1beta1.IdentifiedCallStack) bool {
				resultCallStacks = append(resultCallStacks, *callStack)
				return true
			})

			// Verify results
			if len(tt.expected) != len(resultCallStacks) {
				t.Errorf("Expected %d call stacks, got %d", len(tt.expected), len(resultCallStacks))
				return
			}

			for _, expectedCallStack := range tt.expected {
				found := false
				for _, resultCallStack := range resultCallStacks {
					if compareCallStacks(expectedCallStack, resultCallStack) {
						found = true
						break
					}
				}
				if !found {
					t.Error("Expected call stack not found in results")
				}
			}
		})
	}
}

// Helper function to deeply compare two call stacks
func compareCallStacks(a, b v1beta1.IdentifiedCallStack) bool {
	if a.CallID != b.CallID {
		return false
	}
	return compareCallStackNodes(a.CallStack.Root, b.CallStack.Root)
}

func compareCallStackNodes(a, b v1beta1.CallStackNode) bool {
	if !compareStackFrames(a.Frame, b.Frame) {
		return false
	}
	if len(a.Children) != len(b.Children) {
		return false
	}
	for i := range a.Children {
		if !compareCallStackNodes(a.Children[i], b.Children[i]) {
			return false
		}
	}
	return true
}

func compareStackFrames(a, b v1beta1.StackFrame) bool {
	return a.FileID == b.FileID && a.Lineno == b.Lineno
}

func TestApplicationProfileManagerWithCallStacks(t *testing.T) {
	// Setup test environment
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
	ruleBindingCache := rulebindingcachev1.NewCacheMock("node1")

	am, err := CreateApplicationProfileManager(ctx, cfg, "cluster", k8sClient, storageClient, k8sObjectCacheMock, seccompManagerMock, nil, ruleBindingCache)
	if err != nil {
		t.Fatalf("Failed to create ApplicationProfileManager: %v", err)
	}

	// Prepare container
	container := &containercollection.Container{
		K8s: containercollection.K8sMetadata{
			BasicK8sMetadata: eventtypes.BasicK8sMetadata{
				Namespace:     "ns",
				PodName:       "pod",
				ContainerName: "cont",
			},
		},
		Runtime: containercollection.RuntimeMetadata{
			BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
				ContainerID:        "5fff6a395ce4e6984a9447cc6cfb09f473eaf278498243963fcc944889bc8400",
				ContainerStartedAt: eventtypes.Time(time.Now().UnixNano()),
			},
		},
	}

	sharedWatchedContainerData := &utils.WatchedContainerData{}
	err = ensureInstanceID(container, sharedWatchedContainerData, k8sClient, "cluster")
	if err != nil {
		t.Fatalf("Failed to ensure instance ID: %v", err)
	}
	k8sObjectCacheMock.SetSharedContainerData(container.Runtime.ContainerID, sharedWatchedContainerData)

	// Start container monitoring
	am.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: container,
	})

	// Wait for initialization
	time.Sleep(2 * time.Second)

	// Report call stacks
	callStack1 := v1beta1.IdentifiedCallStack{
		CallID: "open",
		CallStack: v1beta1.CallStack{
			Root: v1beta1.CallStackNode{
				Frame: v1beta1.StackFrame{
					FileID: "1",
					Lineno: "42",
				},
				Children: []v1beta1.CallStackNode{},
			},
		},
	}

	callStack2 := v1beta1.IdentifiedCallStack{
		CallID: "exec",
		CallStack: v1beta1.CallStack{
			Root: v1beta1.CallStackNode{
				Frame: v1beta1.StackFrame{
					FileID: "2",
					Lineno: "84",
				},
				Children: []v1beta1.CallStackNode{
					{
						Frame: v1beta1.StackFrame{
							FileID: "3",
							Lineno: "120",
						},
						Children: []v1beta1.CallStackNode{},
					},
				},
			},
		},
	}

	// Report call stacks and verify they're stored in toSaveCallStacks
	am.ReportIdentifiedCallStack("ns/pod/cont", &callStack1)
	time.Sleep(100 * time.Millisecond)

	// Debug logging for first call stack
	toSaveCallStacks := am.toSaveCallStacks.Get("ns/pod/cont")
	t.Logf("After first report - Number of call stacks in toSave: %d", toSaveCallStacks.Len())
	toSaveCallStacks.Range(func(identifier string, stack *v1beta1.IdentifiedCallStack) bool {
		t.Logf("Found call stack with ID: %s", stack.CallID)
		return true
	})

	am.ReportIdentifiedCallStack("ns/pod/cont", &callStack2)
	time.Sleep(100 * time.Millisecond)

	// Debug logging for second call stack
	t.Logf("After second report - Number of call stacks in toSave: %d", toSaveCallStacks.Len())
	toSaveCallStacks.Range(func(identifier string, stack *v1beta1.IdentifiedCallStack) bool {
		t.Logf("Found call stack with ID: %s", stack.CallID)
		return true
	})

	// Let monitoring run and trigger a save
	time.Sleep(2 * time.Second)

	// Check saved call stacks after first save
	savedCallStacks := am.savedCallStacks.Get("ns/pod/cont")
	t.Logf("After first save - Number of call stacks in saved: %v", savedCallStacks)

	// Let it run for the remaining time
	time.Sleep(2 * time.Second)

	// Report container stopped
	am.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeRemoveContainer,
		Container: container,
	})

	// Wait for final processing
	time.Sleep(2 * time.Second)

	// Debug logging for profiles
	for i, profile := range storageClient.ApplicationProfiles {
		t.Logf("Profile %d:", i)
		t.Logf("  Number of containers: %d", len(profile.Spec.Containers))
		if len(profile.Spec.Containers) > 1 {
			t.Logf("  Call stacks in container[1]: %d", len(profile.Spec.Containers[1].IdentifiedCallStacks))
			for _, cs := range profile.Spec.Containers[1].IdentifiedCallStacks {
				t.Logf("    Call stack ID: %s", cs.CallID)
			}
		}
	}

	// Verify results
	if len(storageClient.ApplicationProfiles) == 0 {
		t.Fatal("No application profiles were created")
	}

	// Get the latest profile
	latestProfile := storageClient.ApplicationProfiles[len(storageClient.ApplicationProfiles)-1]
	if latestProfile.Spec.Containers == nil {
		t.Fatal("Containers slice is nil")
	}
	if len(latestProfile.Spec.Containers) <= 1 {
		t.Fatal("Not enough containers in profile")
	}

	foundCallStacks := latestProfile.Spec.Containers[1].IdentifiedCallStacks

	// Sort both expected and found call stacks
	sortCallStacks := func(cs []v1beta1.IdentifiedCallStack) {
		sort.Slice(cs, func(i, j int) bool {
			return string(cs[i].CallID) < string(cs[j].CallID)
		})
	}

	expectedCallStacks := []v1beta1.IdentifiedCallStack{callStack1, callStack2}
	sortCallStacks(expectedCallStacks)
	sortCallStacks(foundCallStacks)

	t.Logf("Number of profiles: %d", len(storageClient.ApplicationProfiles))
	t.Logf("Latest profile containers: %d", len(latestProfile.Spec.Containers))
	t.Logf("Found call stacks: %d", len(foundCallStacks))

	if len(expectedCallStacks) != len(foundCallStacks) {
		t.Errorf("Number of call stacks doesn't match. Expected %d, got %d",
			len(expectedCallStacks), len(foundCallStacks))
		return
	}

	for i := range expectedCallStacks {
		if !compareCallStacks(expectedCallStacks[i], foundCallStacks[i]) {
			t.Errorf("Call stack mismatch at index %d\nExpected: %+v\nGot: %+v",
				i, expectedCallStacks[i], foundCallStacks[i])
		}
	}
}

func TestCallStackComparison(t *testing.T) {
	tests := []struct {
		name     string
		stack1   v1beta1.IdentifiedCallStack
		stack2   v1beta1.IdentifiedCallStack
		expected bool
	}{
		{
			name: "identical single frame stacks",
			stack1: v1beta1.IdentifiedCallStack{
				CallID: "test",
				CallStack: v1beta1.CallStack{
					Root: v1beta1.CallStackNode{
						Frame: v1beta1.StackFrame{
							FileID: "1",
							Lineno: "42",
						},
						Children: []v1beta1.CallStackNode{},
					},
				},
			},
			stack2: v1beta1.IdentifiedCallStack{
				CallID: "test",
				CallStack: v1beta1.CallStack{
					Root: v1beta1.CallStackNode{
						Frame: v1beta1.StackFrame{
							FileID: "1",
							Lineno: "42",
						},
						Children: []v1beta1.CallStackNode{},
					},
				},
			},
			expected: true,
		},
		{
			name: "different call IDs",
			stack1: v1beta1.IdentifiedCallStack{
				CallID: "test1",
				CallStack: v1beta1.CallStack{
					Root: v1beta1.CallStackNode{
						Frame: v1beta1.StackFrame{
							FileID: "1",
							Lineno: "42",
						},
						Children: []v1beta1.CallStackNode{},
					},
				},
			},
			stack2: v1beta1.IdentifiedCallStack{
				CallID: "test2",
				CallStack: v1beta1.CallStack{
					Root: v1beta1.CallStackNode{
						Frame: v1beta1.StackFrame{
							FileID: "1",
							Lineno: "42",
						},
						Children: []v1beta1.CallStackNode{},
					},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compareCallStacks(tt.stack1, tt.stack2)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestCalculateSHA256CallStackHash(t *testing.T) {
	callStack1 := v1beta1.IdentifiedCallStack{
		CallID: "open",
		CallStack: v1beta1.CallStack{
			Root: v1beta1.CallStackNode{
				Frame: v1beta1.StackFrame{
					FileID: "1",
					Lineno: "42",
				},
				Children: []v1beta1.CallStackNode{},
			},
		},
	}

	callStack2 := v1beta1.IdentifiedCallStack{
		CallID: "exec",
		CallStack: v1beta1.CallStack{
			Root: v1beta1.CallStackNode{
				Frame: v1beta1.StackFrame{
					FileID: "2",
					Lineno: "84",
				},
				Children: []v1beta1.CallStackNode{
					{
						Frame: v1beta1.StackFrame{
							FileID: "3",
							Lineno: "120",
						},
						Children: []v1beta1.CallStackNode{},
					},
				},
			},
		},
	}

	hash1 := CalculateSHA256CallStackHash(callStack1)
	hash2 := CalculateSHA256CallStackHash(callStack2)

	t.Logf("Hash for callStack1: %s", hash1)
	t.Logf("Hash for callStack2: %s", hash2)

	// Different call stacks should produce different hashes
	if hash1 == hash2 {
		t.Error("Different call stacks should have different hashes")
	}

	// Same call stack should produce same hash
	hash1Again := CalculateSHA256CallStackHash(callStack1)
	if hash1 != hash1Again {
		t.Error("Same call stack should produce same hash")
	}

	// Test with children nodes
	childrenCallStack := v1beta1.IdentifiedCallStack{
		CallID: "exec",
		CallStack: v1beta1.CallStack{
			Root: v1beta1.CallStackNode{
				Frame: v1beta1.StackFrame{
					FileID: "2",
					Lineno: "84",
				},
				Children: []v1beta1.CallStackNode{
					{
						Frame: v1beta1.StackFrame{
							FileID: "3",
							Lineno: "120",
						},
						Children: []v1beta1.CallStackNode{},
					},
				},
			},
		},
	}

	hashWithChildren := CalculateSHA256CallStackHash(childrenCallStack)
	t.Logf("Hash for childrenCallStack: %s", hashWithChildren)

	// Different call stack with same root but different children should have different hash
	differentChildrenCallStack := v1beta1.IdentifiedCallStack{
		CallID: "exec",
		CallStack: v1beta1.CallStack{
			Root: v1beta1.CallStackNode{
				Frame: v1beta1.StackFrame{
					FileID: "2",
					Lineno: "84",
				},
				Children: []v1beta1.CallStackNode{
					{
						Frame: v1beta1.StackFrame{
							FileID: "4", // Different FileID
							Lineno: "120",
						},
						Children: []v1beta1.CallStackNode{},
					},
				},
			},
		},
	}

	hashWithDifferentChildren := CalculateSHA256CallStackHash(differentChildrenCallStack)
	t.Logf("Hash for differentChildrenCallStack: %s", hashWithDifferentChildren)
	if hashWithChildren == hashWithDifferentChildren {
		t.Error("Call stacks with different children should have different hashes")
	}
}
