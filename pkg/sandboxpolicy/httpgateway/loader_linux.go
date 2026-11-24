// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package httpgateway

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package httpgateway -cc clang -cflags "-O2 -g -Wall -Werror" -target bpfel -no-global-types redirect bpf/redirect.bpf.c -- -I$BPF_ASM_INCLUDE
//go:generate clang -O2 -g -Wall -Werror -target bpfel -I$BPF_ASM_INCLUDE -c testdata/lsmprobe.bpf.c -o testdata/lsmprobe.bpfel.o

// Options configure the redirect.
type Options struct {
	// PinDir is the bpffs directory of the maps and links. It is created.
	PinDir string
	// CgroupRoot is the cgroup v2 mount the programs attach to.
	CgroupRoot string
	// Gateway is the listener that AI connections are rewritten to. Only an
	// IPv4 address is supported. The zero value redirects nothing.
	Gateway netip.AddrPort
}

// attachments are the programs and where they attach, in attach order.
var attachments = []struct {
	program string
	attach  ebpf.AttachType
}{
	{"gw_sockops", ebpf.AttachCGroupSockOps},
	{"gw_connect4", ebpf.AttachCGroupInet4Connect},
	{"gw_connect6", ebpf.AttachCGroupInet6Connect},
	{"gw_sendmsg4", ebpf.AttachCGroupUDP4Sendmsg},
	{"gw_sendmsg6", ebpf.AttachCGroupUDP6Sendmsg},
}

// Redirect is the loaded redirect: its maps and its links at the cgroup root.
type Redirect struct {
	coll  *ebpf.Collection
	links []link.Link
	// Adopted reports whether Load found the links of an earlier process and
	// kept them attached.
	Adopted bool
}

func linkPin(dir, program string) string { return filepath.Join(dir, "link_"+program) }

// Load loads the programs, creates or reopens the pinned maps, and attaches the
// programs at the cgroup root. Maps and links are pinned under PinDir, so they
// outlive the process: Close leaves the redirect running, and the next Load
// reopens the same maps and swaps its own programs into the links that are
// already attached, without a moment in which nothing is attached.
func Load(opts Options) (*Redirect, error) {
	if opts.PinDir == "" || opts.CgroupRoot == "" {
		return nil, errors.New("httpgateway: PinDir and CgroupRoot are required")
	}
	if opts.Gateway.IsValid() && !opts.Gateway.Addr().Unmap().Is4() {
		return nil, fmt.Errorf("httpgateway: gateway address %s is not IPv4", opts.Gateway.Addr())
	}
	if err := os.MkdirAll(opts.PinDir, 0o700); err != nil {
		return nil, fmt.Errorf("httpgateway: pin directory: %w", err)
	}
	spec, err := loadRedirect()
	if err != nil {
		return nil, fmt.Errorf("httpgateway: load spec: %w", err)
	}
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinByName
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: opts.PinDir}})
	if err != nil {
		return nil, fmt.Errorf("httpgateway: load collection: %w", err)
	}
	r := &Redirect{coll: coll}
	if err := r.SetGateway(opts.Gateway); err != nil {
		r.Close()
		return nil, err
	}
	for _, a := range attachments {
		prog := coll.Programs[a.program]
		if prog == nil {
			r.Close()
			return nil, fmt.Errorf("httpgateway: program %s is missing from the object", a.program)
		}
		pin := linkPin(opts.PinDir, a.program)
		l, err := link.LoadPinnedLink(pin, nil)
		switch {
		case err == nil:
			if err := l.Update(prog); err != nil {
				l.Close()
				r.Close()
				return nil, fmt.Errorf("httpgateway: replace program of %s: %w", a.program, err)
			}
			r.Adopted = true
		case errors.Is(err, fs.ErrNotExist):
			l, err = link.AttachCgroup(link.CgroupOptions{Path: opts.CgroupRoot, Attach: a.attach, Program: prog})
			if err != nil {
				r.Close()
				return nil, fmt.Errorf("httpgateway: attach %s: %w", a.program, err)
			}
			if err := l.Pin(pin); err != nil {
				l.Close()
				r.Close()
				return nil, fmt.Errorf("httpgateway: pin link of %s: %w", a.program, err)
			}
		default:
			r.Close()
			return nil, fmt.Errorf("httpgateway: open pinned link of %s: %w", a.program, err)
		}
		r.links = append(r.links, l)
	}
	return r, nil
}

// Close releases the process's handles. The pinned maps and links stay, so the
// redirect keeps running.
func (r *Redirect) Close() {
	for _, l := range r.links {
		l.Close()
	}
	r.links = nil
	if r.coll != nil {
		r.coll.Close()
		r.coll = nil
	}
}

// Remove detaches the redirect and removes every pin under dir. A directory
// that does not exist is not an error.
func Remove(dir string) error {
	var errs []error
	for _, a := range attachments {
		pin := linkPin(dir, a.program)
		l, err := link.LoadPinnedLink(pin, nil)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			// Not a link this kernel can open: removing the pin still
			// drops the reference that keeps it attached.
			errs = append(errs, os.Remove(pin))
			continue
		}
		errs = append(errs, l.Unpin())
		l.Close()
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return errors.Join(errs...)
	}
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	for _, e := range entries {
		errs = append(errs, os.Remove(filepath.Join(dir, e.Name())))
	}
	errs = append(errs, os.Remove(dir))
	return errors.Join(errs...)
}

// SetGateway sets the listener AI connections are rewritten to. The zero value
// stops the rewrite for every binding.
func (r *Redirect) SetGateway(gw netip.AddrPort) error {
	var value [8]byte
	if gw.IsValid() {
		a := gw.Addr().Unmap().As4()
		copy(value[0:4], a[:])
		binary.BigEndian.PutUint16(value[4:], gw.Port())
	}
	if err := r.coll.Maps["cfg"].Put(uint32(0), value); err != nil {
		return fmt.Errorf("httpgateway: set gateway: %w", err)
	}
	return nil
}

// SetBinding binds a cgroup, or changes its binding.
func (r *Redirect) SetBinding(cgroup uint64, b Binding) error {
	return r.coll.Maps[MapBindings].Put(cgroup, encodeBinding(b))
}

// Binding returns the entry of a cgroup.
func (r *Redirect) Binding(cgroup uint64) (Binding, bool, error) {
	var value [BindingValueSize]byte
	if err := r.coll.Maps[MapBindings].Lookup(cgroup, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return Binding{}, false, nil
		}
		return Binding{}, false, err
	}
	b, err := decodeBinding(value[:])
	return b, err == nil, err
}

// DeleteBinding unbinds a cgroup. An unbound cgroup is not an error.
func (r *Redirect) DeleteBinding(cgroup uint64) error {
	err := r.coll.Maps[MapBindings].Delete(cgroup)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

// SetAIDst adds an address to a binding's AI set. expiry is on the clock of
// bpf_ktime_get_ns (CLOCK_MONOTONIC); 0 never expires.
func (r *Redirect) SetAIDst(binding uint32, addr netip.Addr, expiry uint64) error {
	return r.coll.Maps[MapAIDsts].Put(encodeAIDstKey(binding, addr), expiry)
}

// DeleteAIDst removes an address from a binding's AI set.
func (r *Redirect) DeleteAIDst(binding uint32, addr netip.Addr) error {
	err := r.coll.Maps[MapAIDsts].Delete(encodeAIDstKey(binding, addr))
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

// AddExempt adds a destination range that always keeps its own route.
func (r *Redirect) AddExempt(p netip.Prefix) error {
	return r.coll.Maps[MapExempt].Put(encodeExemptKey(p), uint8(1))
}

// Exempt returns the exempt ranges.
func (r *Redirect) Exempt() ([]netip.Prefix, error) {
	var out []netip.Prefix
	var key [ExemptKeySize]byte
	var value uint8
	it := r.coll.Maps[MapExempt].Iterate()
	for it.Next(&key, &value) {
		p, err := decodeExemptKey(key[:])
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, it.Err()
}

// ReplaceExempt makes the exempt set equal to want. Ranges are added before
// others are removed, so a range in both sets is exempt throughout.
func (r *Redirect) ReplaceExempt(want []netip.Prefix) error {
	have, err := r.Exempt()
	if err != nil {
		return fmt.Errorf("httpgateway: read exempt: %w", err)
	}
	keep := map[[ExemptKeySize]byte]bool{}
	var errs []error
	for _, p := range want {
		keep[encodeExemptKey(p)] = true
		errs = append(errs, r.AddExempt(p))
	}
	for _, p := range have {
		if key := encodeExemptKey(p); !keep[key] {
			if err := r.coll.Maps[MapExempt].Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// Bindings returns every bound cgroup.
func (r *Redirect) Bindings() (map[uint64]Binding, error) {
	out := map[uint64]Binding{}
	var cgroup uint64
	var value [BindingValueSize]byte
	it := r.coll.Maps[MapBindings].Iterate()
	for it.Next(&cgroup, &value) {
		b, err := decodeBinding(value[:])
		if err != nil {
			return nil, err
		}
		out[cgroup] = b
	}
	return out, it.Err()
}

// AIDsts returns every AI set entry with its expiry.
func (r *Redirect) AIDsts() (map[AIDst]uint64, error) {
	out := map[AIDst]uint64{}
	var key [AIDstKeySize]byte
	var expiry uint64
	it := r.coll.Maps[MapAIDsts].Iterate()
	for it.Next(&key, &expiry) {
		k, err := decodeAIDstKey(key[:])
		if err != nil {
			return nil, err
		}
		out[k] = expiry
	}
	return out, it.Err()
}

// Conns returns the live connections.
func (r *Redirect) Conns() (map[ConnKey]Conn, error) {
	out := map[ConnKey]Conn{}
	var key [ConnKeySize]byte
	var value [ConnValueSize]byte
	it := r.coll.Maps[MapConns].Iterate()
	for it.Next(&key, &value) {
		k, err := decodeConnKey(key[:])
		if err != nil {
			return nil, err
		}
		c, err := decodeConn(value[:])
		if err != nil {
			return nil, err
		}
		out[k] = c
	}
	return out, it.Err()
}

// Stats are the programs' counters since the maps were created.
type Stats struct {
	Redirected, RecordedDirect, Established, Closed uint64
	QUICRefused, IPv6Refused, Exempted, GateOpen    uint64
}

// Stats reads the counters.
func (r *Redirect) Stats() (Stats, error) {
	var out Stats
	fields := []*uint64{&out.Redirected, &out.RecordedDirect, &out.Established, &out.Closed, &out.QUICRefused, &out.IPv6Refused, &out.Exempted, &out.GateOpen}
	for i, f := range fields {
		var perCPU []uint64
		if err := r.coll.Maps["stats"].Lookup(uint32(i), &perCPU); err != nil {
			return Stats{}, fmt.Errorf("httpgateway: read counter %d: %w", i, err)
		}
		for _, v := range perCPU {
			*f += v
		}
	}
	return out, nil
}
