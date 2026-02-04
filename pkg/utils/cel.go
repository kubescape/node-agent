package utils

import (
	"fmt"
	"io"
	"net/http"

	celtypes "github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/picatz/xcel"
)

type CelEvent interface {
	CapabilitiesEvent
	DNSEvent
	ExecEvent
	HttpEvent
	IOUring
	LinkEvent
	NetworkEvent
	OpenEvent
	SshEvent
	SyscallEvent
	KmodEvent
	UnshareEvent
	BpfEvent
}

type CelEventImpl struct {
	CelEvent
}

// HttpRequestAccessor provides access to HTTP request fields
// It's a lightweight wrapper around CelEvent that avoids allocations
type HttpRequestAccessor struct {
	HttpEvent CelEvent
}

var isSet = ref.FieldTester(func(target any) bool {
	x := target.(*xcel.Object[CelEvent])
	if x.Raw == nil {
		return false
	}
	return true
})

var requestIsSet = ref.FieldTester(func(target any) bool {
	x := target.(*xcel.Object[HttpRequestAccessor])
	if x.Raw.HttpEvent == nil {
		return false
	}
	return true
})

var CelFields = map[string]*celtypes.FieldType{
	"args": {
		Type:  celtypes.ListType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetArgs(), nil
		}),
	},
	"attrSize": {
		Type:  celtypes.UintType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetAttrSize(), nil
		}),
	},
	"capName": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetCapability(), nil
		}),
	},
	"cmd": {
		Type:  celtypes.UintType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetCmd(), nil
		}),
	},
	"comm": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetComm(), nil
		}),
	},
	"containerId": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetContainerID(), nil
		}),
	},
	"containerName": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetContainer(), nil
		}),
	},
	"cwd": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetCwd(), nil
		}),
	},
	"dstAddr": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetDstEndpoint().Addr, nil
		}),
	},
	"dstIp": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetDstIP(), nil
		}),
	},
	"dstPort": {
		Type:  celtypes.IntType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return int(x.Raw.GetDstPort()), nil
		}),
	},
	"exepath": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetExePath(), nil
		}),
	},
	"flags": {
		Type:  celtypes.ListType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetFlags(), nil
		}),
	},
	"flagsRaw": {
		Type:  celtypes.IntType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return int(x.Raw.GetFlagsRaw()), nil
		}),
	},
	"module": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetModule(), nil
		}),
	},
	"name": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetDNSName(), nil
		}),
	},
	"namespace": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetNamespace(), nil
		}),
	},
	"newPath": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetNewPath(), nil
		}),
	},
	"oldPath": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetOldPath(), nil
		}),
	},
	"opcode": {
		Type:  celtypes.IntType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetOpcode(), nil
		}),
	},
	"path": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetPath(), nil
		}),
	},
	"pcomm": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetPcomm(), nil
		}),
	},
	"pid": {
		Type:  celtypes.UintType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetPID(), nil
		}),
	},
	"pktType": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetPktType(), nil
		}),
	},
	"podName": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetPod(), nil
		}),
	},
	"ppid": {
		Type:  celtypes.UintType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetPpid(), nil
		}),
	},
	"proto": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetProto(), nil
		}),
	},
	"pupperlayer": {
		Type:  celtypes.BoolType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetPupperLayer(), nil
		}),
	},
	"srcPort": {
		Type:  celtypes.IntType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return int(x.Raw.GetSrcPort()), nil
		}),
	},
	"syscallName": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetSyscall(), nil
		}),
	},
	"upperlayer": {
		Type:  celtypes.BoolType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetUpperLayer(), nil
		}),
	},
	"uid": {
		Type:  celtypes.UintType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return x.Raw.GetUid(), nil
		}),
	},
	// HTTP request nested object (no allocation - just wraps the event)
	"request": {
		Type:  nil, // Will be set during registration
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			// Return a wrapped accessor - xcel.NewObject is lightweight (just pointer wrapping)
			accessor := HttpRequestAccessor{HttpEvent: x.Raw}
			obj, _ := xcel.NewObject(accessor)
			return obj, nil
		}),
	},
	"direction": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			return string(x.Raw.GetDirection()), nil
		}),
	},
}

// HttpRequestFields defines CEL fields for the nested http.request object
var HttpRequestFields = map[string]*celtypes.FieldType{
	"headers": {
		Type:  celtypes.MapType,
		IsSet: requestIsSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[HttpRequestAccessor])
			if x.Raw.HttpEvent == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			req := x.Raw.HttpEvent.GetRequest()
			if req != nil {
				return req.Header, nil
			}
			return http.Header{}, nil
		}),
	},
	"host": {
		Type:  celtypes.StringType,
		IsSet: requestIsSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[HttpRequestAccessor])
			if x.Raw.HttpEvent == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			req := x.Raw.HttpEvent.GetRequest()
			if req != nil {
				return req.Host, nil
			}
			return "", nil
		}),
	},
	"method": {
		Type:  celtypes.StringType,
		IsSet: requestIsSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[HttpRequestAccessor])
			if x.Raw.HttpEvent == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			req := x.Raw.HttpEvent.GetRequest()
			if req != nil {
				return req.Method, nil
			}
			return "", nil
		}),
	},
	"url": {
		Type:  celtypes.StringType,
		IsSet: requestIsSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[HttpRequestAccessor])
			if x.Raw.HttpEvent == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			req := x.Raw.HttpEvent.GetRequest()
			if req != nil && req.URL != nil {
				return req.URL.String(), nil
			}
			return "", nil
		}),
	},
	"path": {
		Type:  celtypes.StringType,
		IsSet: requestIsSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[HttpRequestAccessor])
			if x.Raw.HttpEvent == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			req := x.Raw.HttpEvent.GetRequest()
			if req != nil && req.URL != nil {
				return req.URL.Path, nil
			}
			return "", nil
		}),
	},
	"body": {
		Type:  celtypes.StringType,
		IsSet: requestIsSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[HttpRequestAccessor])
			if x.Raw.HttpEvent == nil {
				return nil, fmt.Errorf("celval: object is nil")
			}
			// Try GetBuf() first (for eBPF events)
			buf := x.Raw.HttpEvent.GetBuf()
			if len(buf) > 0 {
				return string(buf), nil
			}
			// Fallback to reading from Request.Body (for test events)
			req := x.Raw.HttpEvent.GetRequest()
			if req != nil && req.Body != nil {
				body, err := io.ReadAll(req.Body)
				if err == nil {
					return string(body), nil
				}
			}
			return "", nil
		}),
	},
}
