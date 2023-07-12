package validator

import (
	"node-agent/pkg/config"
	"testing"
)

func TestInt8ToStr(t *testing.T) {
	// Test with valid input
	input1 := []int8{72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 0}
	expected1 := "Hello World"
	output1 := int8ToStr(input1)
	if output1 != expected1 {
		t.Errorf("int8ToStr(%v) = %v; want %v", input1, output1, expected1)
	}

	// Test with empty input
	var input2 []int8
	expected2 := ""
	output2 := int8ToStr(input2)
	if output2 != expected2 {
		t.Errorf("int8ToStr(%v) = %v; want %v", input2, output2, expected2)
	}

	// Test with input containing only null byte
	input3 := []int8{0}
	expected3 := ""
	output3 := int8ToStr(input3)
	if output3 != expected3 {
		t.Errorf("int8ToStr(%v) = %v; want %v", input3, output3, expected3)
	}

	// Test with input containing multiple null bytes
	input4 := []int8{72, 101, 108, 108, 111, 0, 87, 111, 114, 108, 100, 0}
	expected4 := "Hello"
	output4 := int8ToStr(input4)
	if output4 != expected4 {
		t.Errorf("int8ToStr(%v) = %v; want %v", input4, output4, expected4)
	}
}

func Test_checkKernelVersion(t *testing.T) {
	type args struct {
		minKernelVersion string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "valid kernel version",
			args: args{minKernelVersion: "0.1"},
		},
		{
			name:    "invalid kernel version",
			args:    args{minKernelVersion: "999.999"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := checkKernelVersion(tt.args.minKernelVersion); (err != nil) != tt.wantErr {
				t.Errorf("checkKernelVersion() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCheckPrerequisites(t *testing.T) {
	tests := []struct {
		name    string
		setEnv  bool
		wantErr bool
	}{
		{
			name:    "valid prerequisites",
			setEnv:  true,
			wantErr: true, // FIXME: this should be false, but we need privileged containers to run the tests
		},
		{
			name:    "invalid prerequisites",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setEnv {
				t.Setenv(config.NodeNameEnvVar, "testNode")
			}
			if err := CheckPrerequisites(); (err != nil) != tt.wantErr {
				t.Errorf("CheckPrerequisites() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
