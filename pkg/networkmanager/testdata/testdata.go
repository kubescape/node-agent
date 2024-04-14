package testdata

import _ "embed"

//go:embed cronjob.json
var CronjobJson []byte

//go:embed deployment.json
var DeploymentJson []byte

//go:embed daemonset.json
var DaemonsetJson []byte

//go:embed pod.json
var PodJson []byte
