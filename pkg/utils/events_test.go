package utils

// import (
// 	"reflect"
// 	"testing"

// 	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
// 	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
// )

// func TestNetworkToGeneralEvent(t *testing.T) {
// 	type args struct {
// 		event *tracernetworktype.Event
// 	}
// 	tests := []struct {
// 		name string
// 		args args
// 		want *GeneralEvent
// 	}{
// 		{
// 			name: "Test with valid network event",
// 			args: args{
// 				event: &tracernetworktype.Event{
// 					Pid:   1234,
// 					Comm:  "comm",
// 					Uid:   1000,
// 					Gid:   1000,
// 					Port:  1234,
// 					Proto: "protocol",
// 					WithMountNsID: types.WithMountNsID{
// 						MountNsID: 1234,
// 					},
// 					Event: types.Event{
// 						CommonData: types.CommonData{
// 							Runtime: types.BasicRuntimeMetadata{
// 								ContainerID:          "containerID",
// 								ContainerName:        "container",
// 								ContainerImageName:   "containerImageName",
// 								ContainerImageDigest: "containerImageDigest",
// 							},
// 							K8s: types.K8sMetadata{
// 								BasicK8sMetadata: types.BasicK8sMetadata{
// 									Namespace: "namespace",
// 									PodName:   "pod",
// 								},
// 							},
// 						},
// 						Timestamp: 1234567890,
// 					},
// 				},
// 			},
// 			want: &GeneralEvent{
// 				ProcessDetails: ProcessDetails{
// 					Pid:  1234,
// 					Ppid: 5678,
// 					Comm: "comm",
// 					Cwd:  "cwd",
// 					Uid:  1000,
// 					Gid:  1000,
// 				},
// 				ContainerName: "container",
// 				Namespace:     "namespace",
// 				PodName:       "pod",
// 				MountNsID:     1234,
// 				Timestamp:     1234567890,
// 				EventType:     NetworkEventType,
// 				ContainerID:   "containerID",
// 			},
// 		},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			if got := NetworkToGeneralEvent(tt.args.event); !reflect.DeepEqual(got, tt.want) {
// 				t.Errorf("NetworkToGeneralEvent() = %v, want %v", got, tt.want)
// 			}
// 		})
// 	}
// }
