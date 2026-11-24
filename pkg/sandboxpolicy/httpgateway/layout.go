// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

// Package httpgateway redirects a bound pod's TLS connections to AI addresses
// into the node's sandbox gateway and records which pod owns each connection.
//
// The eBPF programs are loaded by this package with cilium/ebpf and attached
// once at the cgroup root. They are not Inspektor Gadget gadgets: the gadget
// runtime attaches no cgroup socket-address, sockops or iterator programs.
package httpgateway

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// Wire layout of the pinned maps, shared with their readers (the gateway's
// processor and node controller, the DNS feed, the TLS tap). Integers are in
// host byte order; addresses are 16 bytes in network order, IPv4 in its
// IPv6-mapped form. The structs have natural C alignment:
//
//	bindings key    cgroup:u64                                          8 bytes
//	bindings value  binding:u32 posture:u8 gate:u8                      6 bytes, padded to 8
//	ai_dsts key     binding:u32 addr[16]                               20 bytes
//	ai_dsts value   expiry:u64 (kernel monotonic ns, 0: no expiry)      8 bytes
//	conns key       addr[16] port:u16                                  18 bytes
//	conns value     cgroup:u64 pid:u32 binding:u32 addr[16] port:u16   34 bytes, padded to 40
//	exempt key      prefixlen:u32 addr[16]                             20 bytes
//	exempt value    u8                                                  1 byte
//
// A change here is a change for every reader.
const (
	BindingKeySize   = 8
	BindingValueSize = 8
	AIDstKeySize     = 20
	AIDstValueSize   = 8
	ConnKeySize      = 18
	ConnValueSize    = 40
	ExemptKeySize    = 20
	ExemptValueSize  = 1
)

// Names of the pinned maps under the pin directory.
const (
	MapBindings = "bindings"
	MapAIDsts   = "ai_dsts"
	MapConns    = "conns"
	MapExempt   = "exempt"
)

// Posture is what happens to a bound pod's AI connections while the gateway
// cannot serve them.
type Posture uint8

const (
	PostureAllow Posture = 0
	PostureDeny  Posture = 1
)

// Gate is the health-gate state of a binding.
type Gate uint8

const (
	// GateRedirecting: AI connections go to the gateway.
	GateRedirecting Gate = 0
	// GateFailingOpen: new connections keep their own route.
	GateFailingOpen Gate = 1
	// GateRecovering: new connections go to the gateway again, and the
	// direct connections of the fail-open window are not all closed yet.
	GateRecovering Gate = 2
)

// Binding is a bound cgroup's entry.
type Binding struct {
	ID      uint32
	Posture Posture
	Gate    Gate
}

// Conn is what the kernel recorded for one connection to the gateway.
type Conn struct {
	CgroupID  uint64
	PID       uint32 // thread group id in the initial pid namespace
	BindingID uint32
	OrigDst   netip.AddrPort
}

// ConnKey is the pod socket's own address and port.
type ConnKey struct {
	Addr netip.Addr
	Port uint16
}

func encodeBinding(b Binding) [BindingValueSize]byte {
	var out [BindingValueSize]byte
	binary.NativeEndian.PutUint32(out[0:], b.ID)
	out[4] = uint8(b.Posture)
	out[5] = uint8(b.Gate)
	return out
}

func decodeBinding(b []byte) (Binding, error) {
	if len(b) != BindingValueSize {
		return Binding{}, fmt.Errorf("bindings value is %d bytes, want %d", len(b), BindingValueSize)
	}
	out := Binding{ID: binary.NativeEndian.Uint32(b), Posture: Posture(b[4]), Gate: Gate(b[5])}
	if out.Posture > PostureDeny {
		return Binding{}, fmt.Errorf("unknown posture %d in bindings", b[4])
	}
	if out.Gate > GateRecovering {
		return Binding{}, fmt.Errorf("unknown gate state %d in bindings", b[5])
	}
	return out, nil
}

func encodeAIDstKey(binding uint32, addr netip.Addr) [AIDstKeySize]byte {
	var out [AIDstKeySize]byte
	binary.NativeEndian.PutUint32(out[0:], binding)
	a := addr.As16()
	copy(out[4:], a[:])
	return out
}

func encodeConnKey(k ConnKey) [ConnKeySize]byte {
	var out [ConnKeySize]byte
	a := k.Addr.As16()
	copy(out[:16], a[:])
	binary.NativeEndian.PutUint16(out[16:], k.Port)
	return out
}

func decodeConnKey(b []byte) (ConnKey, error) {
	if len(b) != ConnKeySize {
		return ConnKey{}, fmt.Errorf("conns key is %d bytes, want %d", len(b), ConnKeySize)
	}
	return ConnKey{Addr: netip.AddrFrom16([16]byte(b[:16])).Unmap(), Port: binary.NativeEndian.Uint16(b[16:])}, nil
}

func decodeConn(b []byte) (Conn, error) {
	if len(b) != ConnValueSize {
		return Conn{}, fmt.Errorf("conns value is %d bytes, want %d", len(b), ConnValueSize)
	}
	return Conn{
		CgroupID:  binary.NativeEndian.Uint64(b[0:]),
		PID:       binary.NativeEndian.Uint32(b[8:]),
		BindingID: binary.NativeEndian.Uint32(b[12:]),
		OrigDst:   netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[16:32])).Unmap(), binary.NativeEndian.Uint16(b[32:])),
	}, nil
}

// encodeExemptKey returns the LPM key of a prefix. An IPv4 prefix is stored
// under its IPv6-mapped form, 96 bits longer.
func encodeExemptKey(p netip.Prefix) [ExemptKeySize]byte {
	var out [ExemptKeySize]byte
	bits := p.Bits()
	if p.Addr().Is4() {
		bits += 96
	}
	binary.NativeEndian.PutUint32(out[0:], uint32(bits))
	a := p.Masked().Addr().As16()
	copy(out[4:], a[:])
	return out
}
