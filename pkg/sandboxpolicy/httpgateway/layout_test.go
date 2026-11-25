// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package httpgateway

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

// TestLayoutMatchesObject: the sizes other components are built against are
// the sizes of the maps in the compiled object.
func TestLayoutMatchesObject(t *testing.T) {
	spec, err := loadRedirect()
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string][2]uint32{
		MapBindings: {BindingKeySize, BindingValueSize},
		MapAIDsts:   {AIDstKeySize, AIDstValueSize},
		MapConns:    {ConnKeySize, ConnValueSize},
		MapExempt:   {ExemptKeySize, ExemptValueSize},
	} {
		m := spec.Maps[name]
		if m == nil {
			t.Errorf("map %s is missing from the object", name)
			continue
		}
		if m.KeySize != want[0] || m.ValueSize != want[1] {
			t.Errorf("map %s: key %d value %d bytes, layout.go says %d and %d", name, m.KeySize, m.ValueSize, want[0], want[1])
		}
	}
	kill, err := loadSockkill()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{MapAIDsts, MapExempt} {
		a, b := spec.Maps[name], kill.Maps[name]
		if b == nil || a.Type != b.Type || a.KeySize != b.KeySize || a.ValueSize != b.ValueSize || a.MaxEntries != b.MaxEntries || a.Flags != b.Flags {
			t.Errorf("map %s differs between the redirect and the kill objects: %v and %v", name, a, b)
		}
	}
}

// TestLayoutKnownBytes pins the encoding to bytes written out by hand, the
// way a reader in another repository sees them.
func TestLayoutKnownBytes(t *testing.T) {
	u16 := func(v uint16) []byte { return binary.NativeEndian.AppendUint16(nil, v) }
	u32 := func(v uint32) []byte { return binary.NativeEndian.AppendUint32(nil, v) }
	u64 := func(v uint64) []byte { return binary.NativeEndian.AppendUint64(nil, v) }
	mapped := func(a, b, c, d byte) []byte { return []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d} }
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

	binding := encodeBinding(Binding{ID: 7, Posture: PostureDeny, Gate: GateRecovering})
	if want := cat(u32(7), []byte{1, 2, 0, 0}); !bytes.Equal(binding[:], want) {
		t.Errorf("binding value % x, want % x", binding, want)
	}
	if got, err := decodeBinding(binding[:]); err != nil || got != (Binding{ID: 7, Posture: PostureDeny, Gate: GateRecovering}) {
		t.Errorf("decode binding: %+v %v", got, err)
	}
	for _, bad := range [][]byte{cat(u32(1), []byte{2, 0, 0, 0}), cat(u32(1), []byte{0, 3, 0, 0}), {1, 2, 3}} {
		if _, err := decodeBinding(bad); err == nil {
			t.Errorf("decode binding % x: no error", bad)
		}
	}

	ai := encodeAIDstKey(7, netip.MustParseAddr("203.0.113.9"))
	if want := cat(u32(7), mapped(203, 0, 113, 9)); !bytes.Equal(ai[:], want) {
		t.Errorf("ai_dsts key % x, want % x", ai, want)
	}

	key := encodeConnKey(ConnKey{Addr: netip.MustParseAddr("10.1.2.3"), Port: 40000})
	if want := cat(mapped(10, 1, 2, 3), u16(40000)); !bytes.Equal(key[:], want) {
		t.Errorf("conns key % x, want % x", key, want)
	}
	// The same key whether the address is written plain or mapped.
	if again := encodeConnKey(ConnKey{Addr: netip.MustParseAddr("::ffff:10.1.2.3"), Port: 40000}); again != key {
		t.Errorf("conns key of the mapped form % x differs from % x", again, key)
	}
	if got, err := decodeConnKey(key[:]); err != nil || got != (ConnKey{Addr: netip.MustParseAddr("10.1.2.3"), Port: 40000}) {
		t.Errorf("decode conns key: %+v %v", got, err)
	}

	value := cat(u64(0x1122334455), u32(4242), u32(7), mapped(203, 0, 113, 9), u16(443), make([]byte, 6))
	want := Conn{CgroupID: 0x1122334455, PID: 4242, BindingID: 7, OrigDst: netip.MustParseAddrPort("203.0.113.9:443")}
	if got, err := decodeConn(value); err != nil || got != want {
		t.Errorf("decode conns value: %+v %v, want %+v", got, err, want)
	}
	if _, err := decodeConn(value[:34]); err == nil {
		t.Error("decode a 34-byte conns value: no error")
	}

	v4 := encodeExemptKey(netip.MustParsePrefix("10.96.1.1/12"))
	if want := cat(u32(96+12), mapped(10, 96, 0, 0)); !bytes.Equal(v4[:], want) {
		t.Errorf("exempt key of an IPv4 prefix % x, want % x", v4, want)
	}
	v6 := encodeExemptKey(netip.MustParsePrefix("fd00::/8"))
	if want := cat(u32(8), []byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}); !bytes.Equal(v6[:], want) {
		t.Errorf("exempt key of an IPv6 prefix % x, want % x", v6, want)
	}
}
