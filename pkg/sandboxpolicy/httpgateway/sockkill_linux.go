// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package httpgateway

import (
	"errors"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package httpgateway -cc clang -cflags "-O2 -g -Wall -Werror" -target bpfel -no-global-types sockkill bpf/sockkill.bpf.c -- -I$BPF_ASM_INCLUDE

// KillDirect destroys, in the network namespace of the calling thread, the TCP
// connections to port 443 of an address in the binding's AI set that have no
// conns entry. The caller enters the pod's network namespace first, on a
// locked OS thread.
func (r *Redirect) KillDirect(binding uint32) (KillResult, error) {
	spec, err := loadSockkill()
	if err != nil {
		return KillResult{}, fmt.Errorf("httpgateway: load kill spec: %w", err)
	}
	if err := spec.Variables["binding_id"].Set(binding); err != nil {
		return KillResult{}, err
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: map[string]*ebpf.Map{
		MapAIDsts: r.coll.Maps[MapAIDsts],
		MapConns:  r.coll.Maps[MapConns],
	}})
	if err != nil {
		if errors.Is(err, ebpf.ErrNotSupported) {
			return KillResult{}, fmt.Errorf("%w: %v", ErrKillUnsupported, err)
		}
		return KillResult{}, fmt.Errorf("httpgateway: load kill: %w", err)
	}
	defer coll.Close()
	it, err := link.AttachIter(link.IterOptions{Program: coll.Programs["gw_kill"]})
	if err != nil {
		return KillResult{}, fmt.Errorf("httpgateway: attach kill: %w", err)
	}
	defer it.Close()
	reader, err := it.Open()
	if err != nil {
		return KillResult{}, fmt.Errorf("httpgateway: open kill: %w", err)
	}
	// Reading the iterator to its end runs the program on every socket.
	_, err = io.Copy(io.Discard, reader)
	reader.Close()
	if err != nil {
		return KillResult{}, fmt.Errorf("httpgateway: run kill: %w", err)
	}
	var out KillResult
	if err := coll.Variables["seen"].Get(&out.Seen); err != nil {
		return KillResult{}, err
	}
	if err := coll.Variables["destroyed"].Get(&out.Destroyed); err != nil {
		return KillResult{}, err
	}
	return out, nil
}
