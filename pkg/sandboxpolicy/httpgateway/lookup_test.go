// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

package httpgateway

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// processorWorkload is the struct the gateway's processor decodes the answer
// into (kubescape/sandbox-gateway, internal/lookup), copied here so a change
// of the answer's shape fails in this repository.
type processorWorkload struct {
	Namespace  string `json:"namespace"`
	Pod        string `json:"pod"`
	Container  string `json:"container"`
	Controller struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"controller"`
	BindingID uint32 `json:"bindingId"`
	Policies  []struct {
		UID        string `json:"uid"`
		Generation int64  `json:"generation"`
	} `json:"policies"`
}

// shortTempDir returns a directory whose socket paths fit in sun_path.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "gwl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestLookupSocket(t *testing.T) {
	maps := newFakeMaps()
	r := NewReconciler(maps)
	deny := policy("uid-2", 7)
	deny.Deny = true
	states, err := r.Apply([]Pod{pod("a", rootA, 100, policy("uid-1", 3), deny), pod("unprepared", "", 300, policy("uid-1", 3))}, rootA, Rotation{}, now)
	if err != nil {
		t.Fatal(err)
	}
	binding := states[0].BindingID

	path := filepath.Join(shortTempDir(t), "run", "lookup.sock")
	// A socket file an earlier process left behind is replaced.
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	stale.Close()

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- ServeLookup(ctx, path, r.Owner) }()
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}}
	get := func(query string) (int, []byte) {
		t.Helper()
		var lastErr error
		for i := 0; i < 100; i++ {
			resp, err := client.Get("http://lookup" + query)
			if err != nil {
				lastErr = err
				time.Sleep(20 * time.Millisecond) // the server is still starting
				continue
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, body
		}
		t.Fatalf("GET %s: %v", query, lastErr)
		return 0, nil
	}

	status, body := get("/v1/workload?cgroup=101")
	if status != http.StatusOK {
		t.Fatalf("container cgroup: %d %s", status, body)
	}
	var got processorWorkload
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	want := processorWorkload{Namespace: "ns", Pod: "pod-a", Container: "main", BindingID: binding}
	want.Controller.Kind, want.Controller.Name = "Deployment", "app"
	want.Policies = []struct {
		UID        string `json:"uid"`
		Generation int64  `json:"generation"`
	}{{"uid-1", 3}, {"uid-2", 7}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("container cgroup: got %+v, want %+v", got, want)
	}
	// The exact keys of the contract, and no others.
	var keys map[string]json.RawMessage
	_ = json.Unmarshal(body, &keys)
	if len(keys) != 6 {
		t.Errorf("answer has keys %v, want namespace, pod, container, controller, bindingId, policies", keys)
	}

	status, body = get("/v1/workload?cgroup=100")
	got = processorWorkload{}
	if err := json.Unmarshal(body, &got); status != http.StatusOK || err != nil || got.Container != "" || got.BindingID != binding || got.Pod != "pod-a" {
		t.Errorf("pod cgroup: %d %s", status, body)
	}

	for query, wantStatus := range map[string]int{
		"/v1/workload?cgroup=301":  http.StatusNotFound, // selected, not bound
		"/v1/workload?cgroup=9999": http.StatusNotFound,
		"/v1/workload?cgroup=abc":  http.StatusBadRequest,
		"/v1/workload?cgroup=0":    http.StatusBadRequest,
		"/v1/workload":             http.StatusBadRequest,
		"/v1/other":                http.StatusNotFound,
	} {
		if status, body := get(query); status != wantStatus {
			t.Errorf("GET %s: %d %s, want %d", query, status, strings.TrimSpace(string(body)), wantStatus)
		}
	}
	resp, err := client.Post("http://lookup/v1/workload?cgroup=101", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", resp.StatusCode)
	}

	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o660 {
		t.Errorf("socket mode %v %v, want 0660", info.Mode().Perm(), err)
	}
	cancel()
	if err := <-served; err != nil {
		t.Errorf("serve: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("the socket is still there after shutdown: %v", err)
	}
}

func TestLookupRefusesToReplaceAFile(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "lookup.sock")
	if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := ServeLookup(context.Background(), path, func(uint64) (Workload, bool) { return Workload{}, false })
	if err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Errorf("got %v", err)
	}
	if data, _ := os.ReadFile(path); string(data) != "not a socket" {
		t.Error("the file was touched")
	}
}

// An owner with no policies still answers with a list, not null.
func TestLookupPoliciesNeverNull(t *testing.T) {
	h := LookupHandler(func(uint64) (Workload, bool) { return Workload{Pod: "p"}, true })
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() { _ = http.Serve(l, h) }()
	resp, err := http.Get("http://" + netip.MustParseAddrPort(l.Addr().String()).String() + "/v1/workload?cgroup=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"policies":[]`) {
		t.Errorf("answer %s", body)
	}
}
