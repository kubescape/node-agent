package utils

import (
	"fmt"

	celtypes "github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/picatz/xcel"
)

type CelEvent interface {
	CapabilitiesEvent
	DNSEvent
	ExecEvent
	HttpRawEvent
	IOUring
	LinkEvent
	NetworkEvent
	OpenEvent
	SshEvent
	SyscallEvent
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
}
