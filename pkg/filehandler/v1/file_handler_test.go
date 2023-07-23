package filehandler

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime/pprof"
	"testing"
	"time"
)

func TestCreateFsFileHandler(t *testing.T) {
	fh, err := CreateFsFileHandler("/data")
	if err != nil {
		t.Errorf("CreateFsFileHandler() failed: %s", err)
	}
	fh.Close()
}

func TestFsFileHandler_AddFile(t *testing.T) {
	fh, err := CreateFsFileHandler("/tmp")
	if err != nil {
		t.Errorf("CreateFsFileHandler() failed: %s", err)
	}
	defer fh.Close()

	err = fh.AddFile(context.TODO(), "bucket", "file")
	if err != nil {
		t.Errorf("AddFile() failed: %s", err)
	}

	fl, err := fh.GetFiles(context.TODO(), "bucket")
	if err != nil {
		t.Errorf("GetFiles() failed: %s", err)
	}
	if len(fl) != 1 {
		t.Errorf("GetFiles() failed: expected 1 file, got %d", len(fl))
	}
	if !fl["file"] {
		t.Errorf("GetFiles() failed: expected file to be present")
	}
}

func TestFsFileHandler_MultipleThreadAdd(t *testing.T) {
	// Delete all the files that start with bucket in /tmp
	os.RemoveAll("/tmp/bucket*")

	fh, err := CreateFsFileHandler("/tmp")
	if err != nil {
		t.Errorf("CreateFsFileHandler() failed: %s", err)
	}
	defer fh.Close()

	insertFunc := func(i int) {
		log.Printf("Inserting file %d", i)
		// Generate a random file name
		err = fh.AddFile(context.TODO(), "bucket", fmt.Sprintf("file%d", i))
		if err != nil {
			t.Errorf("AddFile() failed: %s", err)
		}
	}

	for i := 0; i < 100; i++ {
		go insertFunc(i)
	}

	// Sleep for 1 second to allow all goroutines to finish
	time.Sleep(1 * time.Second)

	fl, err := fh.GetFiles(context.TODO(), "bucket")
	if err != nil {
		t.Errorf("GetFiles() failed: %s", err)
	}
	if len(fl) != 100 {
		t.Errorf("GetFiles() failed: expected 100 files, got %d", len(fl))
	}
}

func TestProfileLotOfAddFiles(t *testing.T) {
	fh, err := CreateFsFileHandler("/tmp")
	if err != nil {
		t.Errorf("CreateFsFileHandler() failed: %s", err)
	}
	defer fh.Close()

	// Create a file to save the profiling data
	file, err := os.Create("/tmp/cpu_profile.pprof")
	if err != nil {
		t.Errorf("Error creating file: %s", err)
		return
	}
	defer file.Close()

	err = pprof.StartCPUProfile(file)
	if err != nil {
		t.Errorf("Error starting CPU profiling: %s", err)
		return
	}
	defer pprof.StopCPUProfile()

	for i := 0; i < 100000; i++ {
		err := fh.AddFile(context.TODO(), "bucket", fmt.Sprintf("file%d", i))
		if err != nil {
			t.Errorf("AddFile()  failed: %s", err)
		}
	}
}
