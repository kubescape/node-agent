package compactyaml

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	sigsyaml "sigs.k8s.io/yaml"
)

const block = `apiVersion: spdx.softwarecomposition.kubescape.io/v1beta1
kind: ContainerProfile
metadata:
  annotations:
    kubescape.io/managed-by: User
  name: redis-client
  namespace: redis
spec:
  architectures:
  - amd64
  capabilities: []
  egress:
  - dns: ""
    dnsNames: null
    identifier: f8ed3623b37b77eb8ee831996a825efe9cbab4d5ad7edabc2d9799e1b352a844
    ipAddress: ""
    namespaceSelector: null
    podSelector:
      matchLabels:
        app.kubernetes.io/component: master
        app.kubernetes.io/instance: redis
        app.kubernetes.io/name: redis
    ports:
    - name: TCP-6379
      port: 6379
      protocol: TCP
    serviceRefName: redis-master
    serviceRefNamespace: redis
    type: internal
  endpoints: null
  execs:
  - args:
    - /usr/local/bin/redis-cli
    - -h
    - redis-master
    - -p
    - "6379"
    - SET
    - ⋯
    - ⋯
    path: /usr/local/bin/redis-cli
  imageID: docker.io/library/redis@sha256:858f
  matchLabels:
    app: redis-client-auto
  opens:
  - flags:
    - O_CLOEXEC
    - O_DIRECTORY
    - O_RDONLY
    path: /proc/⋯/task/*
  rulePolicies: {}
  seccompProfile:
    spec:
      defaultAction: ""
  syscalls: null
status: {}
`

const compactForm = `apiVersion: spdx.softwarecomposition.kubescape.io/v1beta1
kind: ContainerProfile
metadata:
  annotations:
    kubescape.io/managed-by: User
  name: redis-client
  namespace: redis
spec:
  architectures:
    - amd64
  capabilities: []
  egress:
    - {dns: "", dnsNames: null, identifier: f8ed3623b37b77eb8ee831996a825efe9cbab4d5ad7edabc2d9799e1b352a844, ipAddress: "", namespaceSelector: null, podSelector: {matchLabels: {app.kubernetes.io/component: master, app.kubernetes.io/instance: redis, app.kubernetes.io/name: redis}}, ports: [{name: TCP-6379, port: 6379, protocol: TCP}], serviceRefName: redis-master, serviceRefNamespace: redis, type: internal}
  endpoints: null
  execs:
    - {args: [/usr/local/bin/redis-cli, -h, redis-master, -p, "6379", SET, ⋯, ⋯], path: /usr/local/bin/redis-cli}
  imageID: docker.io/library/redis@sha256:858f
  matchLabels:
    app: redis-client-auto
  opens:
    - {flags: [O_CLOEXEC, O_DIRECTORY, O_RDONLY], path: /proc/⋯/task/*}
  rulePolicies: {}
  seccompProfile:
    spec:
      defaultAction: ""
  syscalls: null
status: {}
`

func TestMarshalMatchesBobctlCompactForm(t *testing.T) {
	var obj map[string]any
	require.NoError(t, sigsyaml.Unmarshal([]byte(block), &obj))
	out, err := Marshal(obj)
	require.NoError(t, err)
	require.Equal(t, compactForm, string(out))
}

func TestMarshalRoundTripsLosslessly(t *testing.T) {
	var obj map[string]any
	require.NoError(t, sigsyaml.Unmarshal([]byte(block), &obj))
	out, err := Marshal(obj)
	require.NoError(t, err)
	var back map[string]any
	require.NoError(t, sigsyaml.Unmarshal(out, &back))
	require.Equal(t, obj, back)
	require.False(t, strings.Contains(string(out), "\t"))
}

func TestMarshalSortsKeysLikeBobctl(t *testing.T) {
	type inner struct {
		Path string   `json:"path"`
		Args []string `json:"args"`
	}
	type spec struct {
		Opens []inner `json:"opens"`
		Execs []inner `json:"execs"`
	}
	out, err := Marshal(struct {
		Kind string `json:"kind"`
		Spec spec   `json:"spec"`
		API  string `json:"apiVersion"`
	}{Kind: "ContainerProfile", API: "v1", Spec: spec{Opens: []inner{{Path: "/x", Args: []string{"a"}}}, Execs: []inner{{Path: "/y", Args: []string{"6379"}}}}})
	require.NoError(t, err)
	require.Equal(t, "apiVersion: v1\nkind: ContainerProfile\nspec:\n  execs:\n    - {args: [\"6379\"], path: /y}\n  opens:\n    - {args: [a], path: /x}\n", string(out))
}
