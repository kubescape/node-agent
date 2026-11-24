// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package httpgateway

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// NetNSKiller runs the socket kill inside each pod's network namespace.
type NetNSKiller struct {
	Redirect *Redirect
}

// Kill closes the pod's direct connections to its AI addresses. A pod on the
// host network is skipped: the iterator walks a whole network namespace, and
// that one holds the connections of every other host-network workload. So is
// a pod whose namespace is not known.
func (k NetNSKiller) Kill(_ context.Context, pod PodState) (KillResult, error) {
	if pod.Pod.HostNetwork || pod.Pod.NetNS == "" {
		return KillResult{}, ErrKillSkipped
	}
	return inNetNS(pod.Pod.NetNS, func() (KillResult, error) { return k.Redirect.KillDirect(pod.BindingID) })
}

// inNetNS runs fn on a thread that has entered the network namespace at path.
// The thread goes back to its own namespace afterwards; if that fails it is
// never handed back to the runtime.
func inNetNS(path string, fn func() (KillResult, error)) (KillResult, error) {
	type result struct {
		res KillResult
		err error
	}
	done := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		target, err := os.Open(path)
		if err != nil {
			runtime.UnlockOSThread()
			done <- result{err: fmt.Errorf("httpgateway: open network namespace %s: %w", path, err)}
			return
		}
		defer target.Close()
		own, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			runtime.UnlockOSThread()
			done <- result{err: fmt.Errorf("httpgateway: open own network namespace: %w", err)}
			return
		}
		defer own.Close()
		if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
			runtime.UnlockOSThread()
			done <- result{err: fmt.Errorf("httpgateway: enter network namespace %s: %w", path, err)}
			return
		}
		res, err := fn()
		if unix.Setns(int(own.Fd()), unix.CLONE_NEWNET) == nil {
			runtime.UnlockOSThread()
		}
		// Otherwise the thread stays locked and ends with this goroutine.
		done <- result{res, err}
	}()
	r := <-done
	return r.res, r.err
}
