// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package httpgateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// DefaultLookupSocket is where the gateway's processor asks which workload
// owns a cgroup. It is a hostPath shared with the gateway pod.
const DefaultLookupSocket = "/run/kubescape-sandbox/lookup.sock"

// LookupPath is the one path the socket serves:
//
//	GET /v1/workload?cgroup=<id>
//	200 {"namespace","pod","container","controller":{"kind","name"},
//	     "bindingId","policies":[{"uid","generation"}]}
//	404 when the cgroup is not bound
//
// The cgroup id is the one in a conns entry. "container" is empty when that
// cgroup is the pod's own. The answer says who the workload is and which
// policy objects cover it; it does not carry their rules.
const LookupPath = "/v1/workload"

// LookupHandler answers workload lookups from owner (the reconciler's Owner).
func LookupHandler(owner func(cgroup uint64) (Workload, bool)) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(LookupPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		cgroup, err := strconv.ParseUint(r.URL.Query().Get("cgroup"), 10, 64)
		if err != nil || cgroup == 0 {
			http.Error(w, "cgroup must be a cgroup id", http.StatusBadRequest)
			return
		}
		workload, ok := owner(cgroup)
		if !ok {
			http.Error(w, "cgroup is not bound", http.StatusNotFound)
			return
		}
		if workload.Policies == nil {
			workload.Policies = []PolicyRef{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(workload)
	})
	return mux
}

// ServeLookup serves workload lookups on the unix socket at path until ctx
// ends, then removes the socket. See ListenLookup for how the socket is made.
func ServeLookup(ctx context.Context, path string, owner func(cgroup uint64) (Workload, bool)) error {
	listener, err := ListenLookup(path)
	if err != nil {
		return err
	}
	return ServeLookupOn(ctx, listener, owner)
}

// ListenLookup creates the lookup socket at path. A socket file left by an
// earlier process is replaced; anything else at path is an error. The socket's
// mode is 0660, so the gateway reaches it through its group.
func ListenLookup(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("httpgateway: lookup socket directory: %w", err)
	}
	info, err := os.Lstat(path)
	switch {
	case err == nil && info.Mode()&fs.ModeSocket == 0:
		return nil, fmt.Errorf("httpgateway: %s exists and is not a socket", path)
	case err == nil:
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("httpgateway: remove the old lookup socket: %w", err)
		}
	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("httpgateway: lookup socket: %w", err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("httpgateway: listen on the lookup socket: %w", err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		listener.Close()
		return nil, fmt.Errorf("httpgateway: lookup socket mode: %w", err)
	}
	return listener, nil
}

// ServeLookupOn serves workload lookups on listener until ctx ends, then
// closes it (which removes a unix socket file).
func ServeLookupOn(ctx context.Context, listener net.Listener, owner func(cgroup uint64) (Workload, bool)) error {
	server := &http.Server{Handler: LookupHandler(owner), ReadHeaderTimeout: 5 * time.Second}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	err := server.Serve(listener)
	<-stopped
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
