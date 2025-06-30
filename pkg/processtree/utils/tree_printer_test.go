package utils

import (
	"testing"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/stretchr/testify/assert"
)

func TestPrintTreeOneLine(t *testing.T) {
	tests := []struct {
		name     string
		process  *apitypes.Process
		expected string
	}{
		{
			name:     "nil process",
			process:  nil,
			expected: "nil",
		},
		{
			name: "single process",
			process: &apitypes.Process{
				PID:  1,
				Comm: "init",
			},
			expected: "init(1)",
		},
		{
			name: "linear chain",
			process: &apitypes.Process{
				PID:  1,
				Comm: "init",
				ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
					{Comm: "systemd", PID: 2}: {
						PID:  2,
						Comm: "systemd",
						ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
							{Comm: "sshd", PID: 3}: {
								PID:  3,
								Comm: "sshd",
							},
						},
					},
				},
			},
			expected: "init(1) -> systemd(2) -> sshd(3)",
		},
		{
			name: "multiple children",
			process: &apitypes.Process{
				PID:  1,
				Comm: "init",
				ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
					{Comm: "systemd", PID: 2}: {
						PID:  2,
						Comm: "systemd",
					},
					{Comm: "kthreadd", PID: 3}: {
						PID:  3,
						Comm: "kthreadd",
					},
				},
			},
			expected: "init(1) -> systemd(2) | init(1) -> kthreadd(3)",
		},
		{
			name: "complex tree",
			process: &apitypes.Process{
				PID:  1,
				Comm: "init",
				ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
					{Comm: "systemd", PID: 2}: {
						PID:  2,
						Comm: "systemd",
						ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
							{Comm: "sshd", PID: 3}: {
								PID:  3,
								Comm: "sshd",
								ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
									{Comm: "bash", PID: 4}: {
										PID:  4,
										Comm: "bash",
									},
									{Comm: "vim", PID: 5}: {
										PID:  5,
										Comm: "vim",
									},
								},
							},
						},
					},
				},
			},
			expected: "init(1) -> systemd(2) -> sshd(3) -> bash(4) | sshd(3) -> vim(5)",
		},
		{
			name: "process without comm",
			process: &apitypes.Process{
				PID: 123,
			},
			expected: "pid(123)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := PrintTreeOneLine(tt.process)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPrintTreeOneLineCompact(t *testing.T) {
	tests := []struct {
		name     string
		process  *apitypes.Process
		expected string
	}{
		{
			name:     "nil process",
			process:  nil,
			expected: "nil",
		},
		{
			name: "linear chain",
			process: &apitypes.Process{
				PID:  1,
				Comm: "init",
				ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
					{Comm: "systemd", PID: 2}: {
						PID:  2,
						Comm: "systemd",
						ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
							{Comm: "sshd", PID: 3}: {
								PID:  3,
								Comm: "sshd",
							},
						},
					},
				},
			},
			expected: "init->systemd->sshd",
		},
		{
			name: "multiple children",
			process: &apitypes.Process{
				PID:  1,
				Comm: "init",
				ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
					{Comm: "systemd", PID: 2}: {
						PID:  2,
						Comm: "systemd",
					},
					{Comm: "kthreadd", PID: 3}: {
						PID:  3,
						Comm: "kthreadd",
					},
				},
			},
			expected: "init->systemd|init->kthreadd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := PrintTreeOneLineCompact(tt.process)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPrintTreeOneLineWithPIDs(t *testing.T) {
	tests := []struct {
		name     string
		process  *apitypes.Process
		expected string
	}{
		{
			name:     "nil process",
			process:  nil,
			expected: "nil",
		},
		{
			name: "linear chain",
			process: &apitypes.Process{
				PID:  1,
				Comm: "init",
				ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
					{Comm: "systemd", PID: 2}: {
						PID:  2,
						Comm: "systemd",
						ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
							{Comm: "sshd", PID: 3}: {
								PID:  3,
								Comm: "sshd",
							},
						},
					},
				},
			},
			expected: "1->2->3",
		},
		{
			name: "multiple children",
			process: &apitypes.Process{
				PID:  1,
				Comm: "init",
				ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
					{Comm: "systemd", PID: 2}: {
						PID:  2,
						Comm: "systemd",
					},
					{Comm: "kthreadd", PID: 3}: {
						PID:  3,
						Comm: "kthreadd",
					},
				},
			},
			expected: "1->2|1->3",
		},
		{
			name: "complex tree",
			process: &apitypes.Process{
				PID:  1,
				Comm: "init",
				ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
					{Comm: "systemd", PID: 2}: {
						PID:  2,
						Comm: "systemd",
						ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
							{Comm: "sshd", PID: 3}: {
								PID:  3,
								Comm: "sshd",
								ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
									{Comm: "bash", PID: 4}: {
										PID:  4,
										Comm: "bash",
									},
									{Comm: "vim", PID: 5}: {
										PID:  5,
										Comm: "vim",
									},
								},
							},
						},
					},
				},
			},
			expected: "1->2->3->4|3->5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := PrintTreeOneLineWithPIDs(tt.process)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Example usage function to demonstrate the different formats
func ExamplePrintTreeOneLine() {
	// Create a sample process tree
	process := &apitypes.Process{
		PID:  1,
		Comm: "init",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "systemd", PID: 2}: {
				PID:  2,
				Comm: "systemd",
				ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
					{Comm: "sshd", PID: 3}: {
						PID:  3,
						Comm: "sshd",
						ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
							{Comm: "bash", PID: 4}: {
								PID:  4,
								Comm: "bash",
							},
							{Comm: "vim", PID: 5}: {
								PID:  5,
								Comm: "vim",
							},
						},
					},
				},
			},
		},
	}

	// Print in different formats
	println("Full format:", PrintTreeOneLine(process))
	println("Compact format:", PrintTreeOneLineCompact(process))
	println("PID-only format:", PrintTreeOneLineWithPIDs(process))
}
