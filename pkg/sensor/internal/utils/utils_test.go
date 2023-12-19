package utils

import (
	"context"
	"reflect"
	"testing"

	sensorDs "node-agent/pkg/sensor/datastructures"

	"github.com/stretchr/testify/assert"
)

func Test_GetFileUNIXOwnership(t *testing.T) {
	uid_tests := []struct {
		name     string
		filePath string
		expected [2]int64
	}{
		{
			name:     "etc_passwd",
			filePath: "/etc/passwd",
			expected: [2]int64{0, 0},
		},
		{
			name:     "etc_doesnt_exist",
			filePath: "/etc/doesnt/exist",
			expected: [2]int64{-1, -1},
		},
	}

	for _, tt := range uid_tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, group, err := GetFileUNIXOwnership(tt.filePath)
			if err != nil {
				t.Log(err)
			}
			ownership := [2]int64{owner, group}
			if !assert.Equal(t, ownership, tt.expected) {
				t.Logf("%s has different value", tt.name)
			}
		})
	}
}

func Test_MakeChangedRootFileInfo(t *testing.T) {
	uid_tests := []struct {
		name        string
		rootDir     string
		filePath    string
		readContent bool
		expected    string
	}{
		{
			name:        "etc_passwd",
			rootDir:     "/",
			filePath:    "/etc/passwd",
			readContent: true,
			expected:    "root",
		},
		{
			name:        "etc_shadow",
			rootDir:     "/",
			filePath:    "/etc/shadow",
			readContent: false,
			expected:    "root",
		},
	}

	for _, tt := range uid_tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			fileInfo, err := MakeChangedRootFileInfo(ctx, tt.rootDir, tt.filePath, tt.readContent)
			if err != nil {
				t.Log(err)
			}

			if !assert.Equal(t, fileInfo.Ownership.Username, tt.expected) {
				t.Logf("%s has different value", tt.name)
			}
		})
	}
}

func Test_MakeFileInfo(t *testing.T) {
	type args struct {
		filePath    string
		readContent bool
	}
	tests := []struct {
		name    string
		args    args
		want    *sensorDs.FileInfo
		wantErr bool
	}{
		{
			name: "test_1",
			args: args{
				filePath:    "./testdata/test_1",
				readContent: true,
			},
			want: &sensorDs.FileInfo{
				Ownership:   &sensorDs.FileOwnership{},
				Path:        "./testdata/test_1",
				Content:     []byte("not empty file"),
				Permissions: 420,
			},
			wantErr: false,
		},
		{
			name: "test_2",
			args: args{
				filePath:    "./testdata/test_2",
				readContent: true,
			},
			want: &sensorDs.FileInfo{
				Ownership:   &sensorDs.FileOwnership{},
				Path:        "./testdata/test_2",
				Content:     []byte(""),
				Permissions: 493,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MakeFileInfo(tt.args.filePath, tt.args.readContent)
			if (err != nil) != tt.wantErr {
				t.Errorf("MakeFileInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got.Content, tt.want.Content) {
				t.Errorf("MakeFileInfo() = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got.Permissions, tt.want.Permissions) {
				t.Errorf("MakeFileInfo() = %v, want %v", got, tt.want)
			}
		})
	}
}
