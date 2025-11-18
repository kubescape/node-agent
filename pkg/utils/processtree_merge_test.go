package utils

import (
	"testing"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/stretchr/testify/assert"
)

func createTestProcess(pid, ppid uint32, comm string) *apitypes.Process {
	return &apitypes.Process{
		PID:         pid,
		PPID:        ppid,
		Comm:        comm,
		Cmdline:     comm + " --args",
		Path:        "/usr/bin/" + comm,
		ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
	}
}

func TestMergeProcessTrees_NilTrees(t *testing.T) {
	// Both nil
	result := MergeProcessTrees(nil, nil)
	assert.Nil(t, result)

	// Target nil
	source := createTestProcess(100, 1, "process1")
	result = MergeProcessTrees(nil, source)
	assert.NotNil(t, result)
	assert.Equal(t, uint32(100), result.PID)

	// Source nil
	target := createTestProcess(100, 1, "process1")
	result = MergeProcessTrees(target, nil)
	assert.Equal(t, target, result)
}

func TestMergeProcessTrees_SingleProcess(t *testing.T) {
	target := createTestProcess(100, 1, "init")
	source := createTestProcess(100, 1, "init")

	result := MergeProcessTrees(target, source)

	assert.Equal(t, uint32(100), result.PID)
	assert.Equal(t, "init", result.Comm)
}

func TestMergeProcessTrees_DifferentProcesses(t *testing.T) {
	// Target: init(100)
	target := createTestProcess(100, 1, "init")

	// Source: init(100) -> child(200)
	source := createTestProcess(100, 1, "init")
	child := createTestProcess(200, 100, "child")
	source.ChildrenMap[apitypes.CommPID{PID: 200}] = child

	result := MergeProcessTrees(target, source)

	// Target should now have the child
	assert.Equal(t, uint32(100), result.PID)
	assert.Equal(t, 1, len(result.ChildrenMap))
	assert.Contains(t, result.ChildrenMap, apitypes.CommPID{PID: 200})
}

func TestMergeProcessTrees_ComplexTree(t *testing.T) {
	// Target tree:
	// init(1) -> bash(100) -> app1(200)
	target := createTestProcess(1, 0, "init")
	bash := createTestProcess(100, 1, "bash")
	app1 := createTestProcess(200, 100, "app1")
	bash.ChildrenMap[apitypes.CommPID{PID: 200}] = app1
	target.ChildrenMap[apitypes.CommPID{PID: 100}] = bash

	// Source tree:
	// init(1) -> bash(100) -> app2(300)
	source := createTestProcess(1, 0, "init")
	bashSrc := createTestProcess(100, 1, "bash")
	app2 := createTestProcess(300, 100, "app2")
	bashSrc.ChildrenMap[apitypes.CommPID{PID: 300}] = app2
	source.ChildrenMap[apitypes.CommPID{PID: 100}] = bashSrc

	result := MergeProcessTrees(target, source)

	// Result should have both app1 and app2 as children of bash
	assert.Equal(t, uint32(1), result.PID)
	assert.Equal(t, 1, len(result.ChildrenMap))

	bashMerged := result.ChildrenMap[apitypes.CommPID{PID: 100}]
	assert.NotNil(t, bashMerged)
	assert.Equal(t, 2, len(bashMerged.ChildrenMap))
	assert.Contains(t, bashMerged.ChildrenMap, apitypes.CommPID{PID: 200})
	assert.Contains(t, bashMerged.ChildrenMap, apitypes.CommPID{PID: 300})
}

func TestMergeProcessTrees_EnrichExisting(t *testing.T) {
	// Target has process with minimal info
	target := createTestProcess(100, 1, "")
	target.Path = ""

	// Source has same process with more info
	source := createTestProcess(100, 1, "bash")
	source.Path = "/bin/bash"

	result := MergeProcessTrees(target, source)

	// Target should be enriched with source's data
	assert.Equal(t, uint32(100), result.PID)
	assert.Equal(t, "bash", result.Comm)
	assert.Equal(t, "/bin/bash", result.Path)
}

func TestMergeCloudServices_Empty(t *testing.T) {
	result := MergeCloudServices([]string{}, []string{})
	assert.Equal(t, 0, len(result))

	result = MergeCloudServices(nil, nil)
	assert.Equal(t, 0, len(result))
}

func TestMergeCloudServices_NoOverlap(t *testing.T) {
	existing := []string{"aws-s3", "aws-ec2"}
	new := []string{"azure-blob", "gcp-storage"}

	result := MergeCloudServices(existing, new)

	assert.Equal(t, 4, len(result))
	assert.Contains(t, result, "aws-s3")
	assert.Contains(t, result, "aws-ec2")
	assert.Contains(t, result, "azure-blob")
	assert.Contains(t, result, "gcp-storage")
}

func TestMergeCloudServices_WithDuplicates(t *testing.T) {
	existing := []string{"aws-s3", "aws-ec2"}
	new := []string{"aws-s3", "azure-blob"}

	result := MergeCloudServices(existing, new)

	// Should deduplicate
	assert.Equal(t, 3, len(result))
	assert.Contains(t, result, "aws-s3")
	assert.Contains(t, result, "aws-ec2")
	assert.Contains(t, result, "azure-blob")

	// Count occurrences of aws-s3 - should be exactly 1
	count := 0
	for _, svc := range result {
		if svc == "aws-s3" {
			count++
		}
	}
	assert.Equal(t, 1, count, "aws-s3 should appear exactly once")
}

func TestMergeCloudServices_OnlyExisting(t *testing.T) {
	existing := []string{"aws-s3", "aws-ec2"}
	new := []string{}

	result := MergeCloudServices(existing, new)

	assert.Equal(t, 2, len(result))
	assert.Contains(t, result, "aws-s3")
	assert.Contains(t, result, "aws-ec2")
}

func TestMergeCloudServices_OnlyNew(t *testing.T) {
	existing := []string{}
	new := []string{"aws-s3", "aws-ec2"}

	result := MergeCloudServices(existing, new)

	assert.Equal(t, 2, len(result))
	assert.Contains(t, result, "aws-s3")
	assert.Contains(t, result, "aws-ec2")
}

func TestTraverseProcessTree(t *testing.T) {
	// Create a tree:
	// init(1) -> bash(100) -> [app1(200), app2(300)]
	root := createTestProcess(1, 0, "init")
	bash := createTestProcess(100, 1, "bash")
	app1 := createTestProcess(200, 100, "app1")
	app2 := createTestProcess(300, 100, "app2")

	bash.ChildrenMap[apitypes.CommPID{PID: 200}] = app1
	bash.ChildrenMap[apitypes.CommPID{PID: 300}] = app2
	root.ChildrenMap[apitypes.CommPID{PID: 100}] = bash

	// Traverse and collect PIDs
	var pids []uint32
	traverseProcessTree(root, func(p *apitypes.Process) {
		pids = append(pids, p.PID)
	})

	// Should have visited all nodes
	assert.Equal(t, 4, len(pids))
	assert.Contains(t, pids, uint32(1))
	assert.Contains(t, pids, uint32(100))
	assert.Contains(t, pids, uint32(200))
	assert.Contains(t, pids, uint32(300))
}

func TestBuildProcessMap(t *testing.T) {
	// Create a tree:
	// init(1) -> bash(100) -> app(200)
	root := createTestProcess(1, 0, "init")
	bash := createTestProcess(100, 1, "bash")
	app := createTestProcess(200, 100, "app")

	bash.ChildrenMap[apitypes.CommPID{PID: 200}] = app
	root.ChildrenMap[apitypes.CommPID{PID: 100}] = bash

	processMap := buildProcessMap(root)

	assert.Equal(t, 3, len(processMap))
	assert.Contains(t, processMap, uint32(1))
	assert.Contains(t, processMap, uint32(100))
	assert.Contains(t, processMap, uint32(200))

	assert.Equal(t, "init", processMap[1].Comm)
	assert.Equal(t, "bash", processMap[100].Comm)
	assert.Equal(t, "app", processMap[200].Comm)
}

