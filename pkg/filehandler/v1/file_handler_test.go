package filehandler

import (
	"context"
	"reflect"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestBoltFileHandler_AddFile(t *testing.T) {
	type fields struct {
		fileDB *bolt.DB
	}
	type args struct {
		ctx    context.Context
		bucket string
		file   string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := BoltFileHandler{
				fileDB: tt.fields.fileDB,
			}
			if err := b.AddFile(tt.args.ctx, tt.args.bucket, tt.args.file); (err != nil) != tt.wantErr {
				t.Errorf("AddFile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBoltFileHandler_Close(t *testing.T) {
	type fields struct {
		fileDB *bolt.DB
	}
	tests := []struct {
		name   string
		fields fields
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := BoltFileHandler{
				fileDB: tt.fields.fileDB,
			}
			b.Close()
		})
	}
}

func TestBoltFileHandler_GetFiles(t *testing.T) {
	type fields struct {
		fileDB *bolt.DB
	}
	type args struct {
		ctx       context.Context
		container string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    map[string]bool
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := BoltFileHandler{
				fileDB: tt.fields.fileDB,
			}
			got, err := b.GetFiles(tt.args.ctx, tt.args.container)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetFiles() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetFiles() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBoltFileHandler_RemoveBucket(t *testing.T) {
	type fields struct {
		fileDB *bolt.DB
	}
	type args struct {
		ctx    context.Context
		bucket string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := BoltFileHandler{
				fileDB: tt.fields.fileDB,
			}
			if err := b.RemoveBucket(tt.args.ctx, tt.args.bucket); (err != nil) != tt.wantErr {
				t.Errorf("RemoveBucket() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCreateBoltFileHandler(t *testing.T) {
	tests := []struct {
		name    string
		want    *BoltFileHandler
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CreateBoltFileHandler()
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateBoltFileHandler() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreateBoltFileHandler() got = %v, want %v", got, tt.want)
			}
		})
	}
}
