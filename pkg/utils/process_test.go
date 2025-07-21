package utils

import (
	"testing"

	apitypes "github.com/armosec/armoapi-go/armotypes"
)

func TestCalculateProcessTreeDepth(t *testing.T) {
	tests := []struct {
		name     string
		process  *apitypes.Process
		expected int
	}{
		{
			name:     "nil process",
			process:  nil,
			expected: 0,
		},
		{
			name: "single process with no children",
			process: &apitypes.Process{
				PID:         1,
				Comm:        "init",
				ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
			},
			expected: 1,
		},
		{
			name: "process with one level of children",
			process: &apitypes.Process{
				PID:  1,
				Comm: "init",
				ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
					{Comm: "child1", PID: 2}: {
						PID:         2,
						Comm:        "child1",
						PPID:        1,
						ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
					},
					{Comm: "child2", PID: 3}: {
						PID:         3,
						Comm:        "child2",
						PPID:        1,
						ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
					},
				},
			},
			expected: 2,
		},
		{
			name: "process with multiple levels",
			process: &apitypes.Process{
				PID:  1,
				Comm: "init",
				ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
					{Comm: "child1", PID: 2}: {
						PID:  2,
						Comm: "child1",
						PPID: 1,
						ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
							{Comm: "grandchild1", PID: 4}: {
								PID:         4,
								Comm:        "grandchild1",
								PPID:        2,
								ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
							},
						},
					},
					{Comm: "child2", PID: 3}: {
						PID:         3,
						Comm:        "child2",
						PPID:        1,
						ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
					},
				},
			},
			expected: 3,
		},
		{
			name: "process with deep nesting",
			process: &apitypes.Process{
				PID:  1,
				Comm: "root",
				ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
					{Comm: "level1", PID: 2}: {
						PID:  2,
						Comm: "level1",
						PPID: 1,
						ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
							{Comm: "level2", PID: 3}: {
								PID:  3,
								Comm: "level2",
								PPID: 2,
								ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
									{Comm: "level3", PID: 4}: {
										PID:  4,
										Comm: "level3",
										PPID: 3,
										ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
											{Comm: "level4", PID: 5}: {
												PID:         5,
												Comm:        "level4",
												PPID:        4,
												ChildrenMap: make(map[apitypes.CommPID]*apitypes.Process),
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculateProcessTreeDepth(tt.process)
			if result != tt.expected {
				t.Errorf("CalculateProcessTreeDepth() = %d, expected %d", result, tt.expected)
			}
		})
	}
}
