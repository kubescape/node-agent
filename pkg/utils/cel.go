package utils

import (
	"bytes"
	"errors"
	"io"
	"net/http"

	celtypes "github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/picatz/xcel"
)

// errCelObjectNil is returned by FieldGetter callbacks when the underlying
// event is nil. Reused across all getters to avoid per-call error allocation
// on the CEL hot path.
var errCelObjectNil = errors.New("celval: object is nil")

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

var isSet = ref.FieldTester(func(target any) bool {
	x := target.(*xcel.Object[CelEvent])
	if x.Raw == nil {
		return false
	}
	return true
})

var requestIsSet = ref.FieldTester(func(target any) bool {
	x := target.(*xcel.Object[CelEvent])
	if x.Raw == nil {
		return false
	}
	return x.Raw.GetRequest() != nil
})

var urlIsSet = ref.FieldTester(func(target any) bool {
	x := target.(*xcel.Object[CelEvent])
	if x.Raw == nil {
		return false
	}
	req := x.Raw.GetRequest()
	return req != nil && req.URL != nil
})

// presenceOf builds a field tester backed by the datasource field name dsField,
// so CEL has(event.x) reports whether the running gadget actually emits the
// underlying signal. Without this, an absent field is indistinguishable from a
// zero value and rules cannot tell "no terminal" from "not measured".
func presenceOf(dsField string) ref.FieldTester {
	return ref.FieldTester(func(target any) bool {
		x := target.(*xcel.Object[CelEvent])
		if x.Raw == nil {
			return false
		}
		return x.Raw.FieldPresent(dsField)
	})
}

// CelFields is the field registry exposed to rule expressions as `event.<name>`.
//
// A field whose IsSet tester is presenceOf(...) can be absent at runtime when
// the running gadget does not emit it; rules should guard those with has().
// See docs/features/exec-tty-field.md for the tty fields specifically.
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
	// dstNamespace / dstPodLabels carry the peer identity that IG's
	// kubeipresolver resolves cluster-wide (independent of node-agent's
	// node-local pod cache), so selector rules can match a peer on any node.
	"dstNamespace": {
		Type:  celtypes.StringType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.String(x.Raw.GetDstEndpoint().Namespace), nil
		}),
	},
	"dstPodLabels": {
		Type:  celtypes.MapType,
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			pl := x.Raw.GetDstEndpoint().PodLabels
			if pl == nil {
				pl = map[string]string{}
			}
			return pl, nil
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
	"hasTty": {
		Type:  celtypes.BoolType,
		IsSet: presenceOf("tty"),
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.Bool(x.Raw.GetHasTTY()), nil
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
	"tty": {
		Type:  celtypes.IntType,
		IsSet: presenceOf("tty"),
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.Int(x.Raw.GetTTY()), nil
		}),
	},
	"ttyMajor": {
		Type:  celtypes.UintType,
		IsSet: presenceOf("tty_major"),
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.Uint(x.Raw.GetTTYMajor()), nil
		}),
	},
	"ttyMinor": {
		Type:  celtypes.UintType,
		IsSet: presenceOf("tty_minor"),
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return celtypes.Uint(x.Raw.GetTTYMinor()), nil
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
			return x.Raw.GetUid(), nil
		}),
	},
	// HTTP request nested object - returns the same *xcel.Object[CelEvent] so
	// HttpRequestFields can read x.Raw.GetRequest() without allocating a wrapper.
	// CEL field dispatch uses the bound FieldType (HttpRequest), not the runtime
	// Go type, so no separate Go-type registration is needed.
	"request": {
		Type:  nil, // Will be set during registration
		IsSet: isSet,
		GetFrom: ref.FieldGetter(func(target any) (any, error) {
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			return target, nil
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
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			req := x.Raw.GetRequest()
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
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			req := x.Raw.GetRequest()
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
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			req := x.Raw.GetRequest()
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
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			req := x.Raw.GetRequest()
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
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			req := x.Raw.GetRequest()
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
			x := target.(*xcel.Object[CelEvent])
			if x.Raw == nil {
				return nil, errCelObjectNil
			}
			// Try GetBuf() first (for eBPF events)
			buf := x.Raw.GetBuf()
			if len(buf) > 0 {
				return celtypes.String(buf), nil
			}
			// Fallback to reading from Request.Body (for test events)
			req := x.Raw.GetRequest()
			if req != nil && req.Body != nil {
				// Read with size limit (10MB) and restore body for downstream readers
				const maxBodySize = 10 * 1024 * 1024 // 10MB
				limitedReader := io.LimitReader(req.Body, maxBodySize)
				bodyBytes, err := io.ReadAll(limitedReader)
				req.Body.Close()                                    // Close the original body
				req.Body = io.NopCloser(bytes.NewReader(bodyBytes)) // Restore for downstream
				if err != nil {
					return "", err
				}
				return celtypes.String(bodyBytes), nil
			}
			return celtypes.String(""), nil
		}),
	},
}
