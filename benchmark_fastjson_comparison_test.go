package main

import (
	"encoding/json"
	"testing"

	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	igtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/valyala/fastjson"
)

// ExecEventWithToMap extends the exec event with ToMap method
type ExecEventWithToMap struct {
	tracerexectype.Event
}

// ToMap converts the exec event to a map[string]interface{}
func (e *ExecEventWithToMap) ToMap() map[string]interface{} {
	result := make(map[string]interface{})

	// Add all exec event fields
	result["pid"] = e.Pid
	result["tid"] = e.Tid
	result["ppid"] = e.Ppid
	result["ptid"] = e.Ptid
	result["comm"] = e.Comm
	result["pcomm"] = e.Pcomm
	result["ret"] = e.Retval
	result["args"] = e.Args
	result["uid"] = e.Uid
	result["user"] = e.Username
	result["gid"] = e.Gid
	result["group"] = e.Groupname
	result["upperlayer"] = e.UpperLayer
	result["pupperlayer"] = e.PupperLayer
	result["loginuid"] = e.LoginUid
	result["sessionid"] = e.SessionId
	result["cwd"] = e.Cwd
	result["exepath"] = e.ExePath
	result["file"] = e.File
	result["mountnsid"] = e.MountNsID

	// Runtime metadata
	if e.Runtime != (igtypes.BasicRuntimeMetadata{}) {
		runtime := make(map[string]interface{})
		runtime["containerid"] = e.Runtime.ContainerID
		runtime["containername"] = e.Runtime.ContainerName
		runtime["containerimagename"] = e.Runtime.ContainerImageName
		runtime["containerimagedigest"] = e.Runtime.ContainerImageDigest
		result["runtime"] = runtime
	}

	// K8s metadata
	if e.K8s.BasicK8sMetadata.Namespace != "" || e.K8s.BasicK8sMetadata.PodName != "" || e.K8s.BasicK8sMetadata.ContainerName != "" {
		k8s := make(map[string]interface{})
		k8s["node"] = e.K8s.Node
		k8s["hostnetwork"] = e.K8s.HostNetwork
		k8s["namespace"] = e.K8s.BasicK8sMetadata.Namespace
		k8s["podname"] = e.K8s.BasicK8sMetadata.PodName
		k8s["containername"] = e.K8s.BasicK8sMetadata.ContainerName
		result["k8s"] = k8s
	}

	return result
}

// createSampleExecEvent creates a sample exec event for benchmarking
func createSampleExecEvent() *tracerexectype.Event {
	return &tracerexectype.Event{
		Event: igtypes.Event{
			CommonData: igtypes.CommonData{
				Runtime: igtypes.BasicRuntimeMetadata{
					ContainerID:          "test-container-id-12345",
					ContainerName:        "test-container",
					ContainerImageName:   "nginx:latest",
					ContainerImageDigest: "sha256:abcdef1234567890",
				},
				K8s: igtypes.K8sMetadata{
					Node:        "worker-node-01",
					HostNetwork: false,
					BasicK8sMetadata: igtypes.BasicK8sMetadata{
						Namespace:     "default",
						PodName:       "nginx-deployment-7d8f9c8b4d-xyz123",
						ContainerName: "nginx",
					},
				},
			},
		},
		WithMountNsID: igtypes.WithMountNsID{
			MountNsID: 4026531840,
		},
		Pid:         12345,
		Tid:         12345,
		Ppid:        1234,
		Ptid:        1234,
		Comm:        "nginx",
		Pcomm:       "systemd",
		Retval:      0,
		Args:        []string{"nginx", "-g", "daemon off;"},
		Uid:         1000,
		Username:    "nginx",
		Gid:         1000,
		Groupname:   "nginx",
		UpperLayer:  false,
		PupperLayer: false,
		LoginUid:    1000,
		SessionId:   123,
		Cwd:         "/var/www/html",
		ExePath:     "/usr/sbin/nginx",
		File:        "/usr/sbin/nginx",
	}
}

// BenchmarkStandardJSON benchmarks standard JSON marshal + unmarshal to map[string]interface{}
func BenchmarkStandardJSON(b *testing.B) {
	event := createSampleExecEvent()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Marshal to JSON
		jsonData, err := json.Marshal(event)
		if err != nil {
			b.Fatal(err)
		}

		// Unmarshal to map[string]interface{}
		var eventMap map[string]interface{}
		err = json.Unmarshal(jsonData, &eventMap)
		if err != nil {
			b.Fatal(err)
		}

		_ = eventMap
	}
}

// BenchmarkFastJSON benchmarks fastjson marshal + parse to map[string]interface{}
func BenchmarkFastJSON(b *testing.B) {
	event := createSampleExecEvent()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Marshal to JSON using standard library (fastjson doesn't have marshal)
		jsonData, err := json.Marshal(event)
		if err != nil {
			b.Fatal(err)
		}

		// Parse with fastjson and convert to map
		var p fastjson.Parser
		v, err := p.ParseBytes(jsonData)
		if err != nil {
			b.Fatal(err)
		}

		// Convert to map[string]interface{}
		eventMap := make(map[string]interface{})
		v.GetObject().Visit(func(key []byte, val *fastjson.Value) {
			switch val.Type() {
			case fastjson.TypeString:
				eventMap[string(key)] = string(val.GetStringBytes())
			case fastjson.TypeNumber:
				eventMap[string(key)] = val.GetFloat64()
			case fastjson.TypeTrue:
				eventMap[string(key)] = true
			case fastjson.TypeFalse:
				eventMap[string(key)] = false
			case fastjson.TypeNull:
				eventMap[string(key)] = nil
			case fastjson.TypeObject:
				// For nested objects, convert recursively
				nestedMap := make(map[string]interface{})
				val.GetObject().Visit(func(nestedKey []byte, nestedVal *fastjson.Value) {
					switch nestedVal.Type() {
					case fastjson.TypeString:
						nestedMap[string(nestedKey)] = string(nestedVal.GetStringBytes())
					case fastjson.TypeNumber:
						nestedMap[string(nestedKey)] = nestedVal.GetFloat64()
					case fastjson.TypeTrue:
						nestedMap[string(nestedKey)] = true
					case fastjson.TypeFalse:
						nestedMap[string(nestedKey)] = false
					}
				})
				eventMap[string(key)] = nestedMap
			case fastjson.TypeArray:
				// For arrays, convert to []interface{}
				arr := val.GetArray()
				result := make([]interface{}, len(arr))
				for j, item := range arr {
					switch item.Type() {
					case fastjson.TypeString:
						result[j] = string(item.GetStringBytes())
					case fastjson.TypeNumber:
						result[j] = item.GetFloat64()
					}
				}
				eventMap[string(key)] = result
			}
		})

		_ = eventMap
	}
}

// BenchmarkToMapMethod benchmarks the custom ToMap method
func BenchmarkToMapMethod(b *testing.B) {
	event := createSampleExecEvent()
	eventWithToMap := &ExecEventWithToMap{Event: *event}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eventMap := eventWithToMap.ToMap()
		_ = eventMap
	}
}
