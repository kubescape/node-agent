package utils

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"sync"

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

var errCelObjectNil = errors.New("celval: object is nil")

var httpRequestType *celtypes.Type

// SetHttpRequestType sets the CEL type used by HttpEventWrapper.
func SetHttpRequestType(t *celtypes.Type) {
	httpRequestType = t
}

// HttpEventWrapper wraps a CelEvent for HTTP request field dispatch.
// It implements ref.Val so it can be returned directly from the "request"
// field getter without allocating an xcel.Object on every access.
type HttpEventWrapper struct {
	CelEvent
}

var HttpEventWrapperPool = sync.Pool{
	New: func() any { return &HttpEventWrapper{} },
}

func (w *HttpEventWrapper) ConvertToNative(typeDesc reflect.Type) (any, error) {
	if typeDesc == reflect.TypeOf(w) {
		return w, nil
	}
	return nil, fmt.Errorf("unsupported conversion to %v", typeDesc)
}

func (w *HttpEventWrapper) ConvertToType(typeValue ref.Type) ref.Val {
	if typeValue == w.Type() {
		return w
	}
	return celtypes.NewErr("type conversion error")
}

func (w *HttpEventWrapper) Equal(other ref.Val) ref.Val {
	return celtypes.Bool(other == w)
}

func (w *HttpEventWrapper) Type() ref.Type {
	if httpRequestType == nil {
		return celtypes.ErrType
	}
	return httpRequestType
}

func (w *HttpEventWrapper) Value() any {
	return w
}

var isSet = ref.FieldTester(func(target any) bool {
	x := target.(*xcel.Object[CelEvent])
	if x.Raw == nil {
		return false
	}
	return true
})

var requestFieldIsSet = ref.FieldTester(func(target any) bool {
	x := target.(*xcel.Object[CelEvent])
	if x.Raw == nil {
		return false
	}
	_, ok := x.Raw.(*HttpEventWrapper)
	return ok
})

var requestIsSet = ref.FieldTester(func(target any) bool {
	x, ok := target.(*HttpEventWrapper)
	return ok && x.CelEvent != nil && x.GetRequest() != nil
})

var urlIsSet = ref.FieldTester(func(target any) bool {
	x, ok := target.(*HttpEventWrapper)
	if !ok || x.CelEvent == nil {
		return false
	}
	req := x.GetRequest()
	if req == nil || req.URL == nil {
		return false
	}
	return req.URL.String() != ""
})

var CelFields = map[string]*celtypes.FieldType{
	"args": {
		Type:  celtypes.ListType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
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
				return nil, errCelObjectNil
			}
			return celtypes.Uint(x.Raw.GetAttrSize()), nil
		}),
	},
	"capName": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.String(x.Raw.GetCapability()), nil
		}),
	},
	"cmd": {
		Type:  celtypes.UintType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.Uint(x.Raw.GetCmd()), nil
		}),
	},
	"comm": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.String(x.Raw.GetComm()), nil
		}),
	},
	"containerId": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.String(x.Raw.GetContainerID()), nil
		}),
	},
	"containerName": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.String(x.Raw.GetContainer()), nil
		}),
	},
	"cwd": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.String(x.Raw.GetCwd()), nil
		}),
	},
	"dstAddr": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.String(x.Raw.GetDstEndpoint().Addr), nil
		}),
	},
	"dstIp": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.String(x.Raw.GetDstIP()), nil
		}),
	},
	"dstPort": {
		Type:  celtypes.IntType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.Int(x.Raw.GetDstPort()), nil
		}),
	},
	"exepath": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.String(x.Raw.GetExePath()), nil
		}),
	},
	"flags": {
		Type:  celtypes.ListType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
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
				return nil, errCelObjectNil
			}
			return celtypes.Int(x.Raw.GetFlagsRaw()), nil
		}),
	},
	"module": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.String(x.Raw.GetModule()), nil
		}),
	},
	"name": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.String(x.Raw.GetDNSName()), nil
		}),
	},
	"namespace": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.String(x.Raw.GetNamespace()), nil
		}),
	},
	"newPath": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.String(x.Raw.GetNewPath()), nil
		}),
	},
	"oldPath": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.String(x.Raw.GetOldPath()), nil
		}),
	},
	"opcode": {
		Type:  celtypes.IntType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.Int(x.Raw.GetOpcode()), nil
		}),
	},
	"path": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.String(x.Raw.GetPath()), nil
		}),
	},
	"pcomm": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.String(x.Raw.GetPcomm()), nil
		}),
	},
	"pid": {
		Type:  celtypes.UintType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.Uint(x.Raw.GetPID()), nil
		}),
	},
	"pktType": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.String(x.Raw.GetPktType()), nil
		}),
	},
	"podName": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.String(x.Raw.GetPod()), nil
		}),
	},
	"ppid": {
		Type:  celtypes.UintType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.Uint(x.Raw.GetPpid()), nil
		}),
	},
	"proto": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.String(x.Raw.GetProto()), nil
		}),
	},
	"pupperlayer": {
		Type:  celtypes.BoolType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.Bool(x.Raw.GetPupperLayer()), nil
		}),
	},
	"srcPort": {
		Type:  celtypes.IntType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.Int(x.Raw.GetSrcPort()), nil
		}),
	},
	"syscallName": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.String(x.Raw.GetSyscall()), nil
		}),
	},
	"upperlayer": {
		Type:  celtypes.BoolType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.Bool(x.Raw.GetUpperLayer()), nil
		}),
	},
	"uid": {
		Type:  celtypes.UintType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			uid := x.Raw.GetUid()
			if uid == nil {
				return celtypes.Uint(0), nil
			}
			return celtypes.Uint(*uid), nil
		}),
	},
	"request": {
		Type:  nil, // Set during registration
		IsSet: requestFieldIsSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			w, ok := x.Raw.(*HttpEventWrapper)
			if !ok {
				return nil, errCelObjectNil
			}
			return w, nil
		}),
	},
	"direction": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.String(x.Raw.GetDirection()), nil
		}),
	},
}

// HttpRequestFields defines CEL fields for the nested http.request object
var HttpRequestFields = map[string]*celtypes.FieldType{
	"headers": {
		Type:  celtypes.MapType,
		IsSet: requestIsSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*HttpEventWrapper)
			if x.CelEvent == nil {
				return nil, errCelObjectNil
			}
			req := x.GetRequest()
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
			x := target.(*HttpEventWrapper)
			if x.CelEvent == nil {
				return nil, errCelObjectNil
			}
			req := x.GetRequest()
			if req != nil {
				return celtypes.String(req.Host), nil
			}
			return celtypes.String(""), nil
		}),
	},
	"method": {
		Type:  celtypes.StringType,
		IsSet: requestIsSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*HttpEventWrapper)
			if x.CelEvent == nil {
				return nil, errCelObjectNil
			}
			req := x.GetRequest()
			if req != nil {
				return celtypes.String(req.Method), nil
			}
			return celtypes.String(""), nil
		}),
	},
	"url": {
		Type:  celtypes.StringType,
		IsSet: urlIsSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*HttpEventWrapper)
			if x.CelEvent == nil {
				return nil, errCelObjectNil
			}
			req := x.GetRequest()
			if req != nil && req.URL != nil {
				return celtypes.String(req.URL.String()), nil
			}
			return celtypes.String(""), nil
		}),
	},
	"path": {
		Type:  celtypes.StringType,
		IsSet: urlIsSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*HttpEventWrapper)
			if x.CelEvent == nil {
				return nil, errCelObjectNil
			}
			req := x.GetRequest()
			if req != nil && req.URL != nil {
				return celtypes.String(req.URL.Path), nil
			}
			return celtypes.String(""), nil
		}),
	},
	"body": {
		Type:  celtypes.StringType,
		IsSet: requestIsSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*HttpEventWrapper)
			if x.CelEvent == nil {
				return nil, errCelObjectNil
			}
			// Try GetBuf() first (for eBPF events)
			buf := x.GetBuf()
			if len(buf) > 0 {
				return celtypes.String(buf), nil
			}
			// Fallback to reading from Request.Body (for test events)
			req := x.GetRequest()
			if req != nil && req.Body != nil {
				// Read with size limit (10MB) and restore body for downstream readers
				const maxBodySize = 10 * 1024 * 1024 // 10MB
				limitedReader := io.LimitReader(req.Body, maxBodySize)
				bodyBytes, err := io.ReadAll(limitedReader)
				req.Body.Close()                                    // Close the original body
				req.Body = io.NopCloser(bytes.NewReader(bodyBytes)) // Restore for downstream
				if err != nil {
					return celtypes.String(""), err
				}
				return celtypes.String(bodyBytes), nil
			}
			return celtypes.String(""), nil
		}),
	},
}
