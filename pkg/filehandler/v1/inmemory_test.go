package filehandler

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddFile(t *testing.T) {
	type args struct {
		bucket string
		file   string
	}
	tests := []struct {
		name    string
		args    args
		wantErr assert.ErrorAssertionFunc
	}{
		{
			"Add a file to an empty bucket",
			args{
				bucket: "testBucket1",
				file:   "testFile1",
			},
			assert.NoError,
		},
		{
			"Add a file to a non-empty bucket",
			args{
				bucket: "testBucket1",
				file:   "testFile2",
			},
			assert.NoError,
		},
	}

	fileHandler, _ := CreateInMemoryFileHandler()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := fileHandler.AddFile(tt.args.bucket, tt.args.file)

			if !tt.wantErr(t, err) {
				return
			}

			// Assert that the file exists in the bucket
			files, _ := fileHandler.GetFiles(tt.args.bucket)
			_, exists := files[tt.args.file]
			assert.Truef(t, exists, "Expected file %v in bucket %v", tt.args.file, tt.args.bucket)
		})
	}

	t.Run("Race condition check", func(t *testing.T) {
		const routines = 1000
		wg := &sync.WaitGroup{}
		wg.Add(routines)

		for i := 0; i < routines; i++ {
			go func(id int) {
				defer wg.Done()
				err := fileHandler.AddFile("concurrentBucket", fmt.Sprintf("testFile%d", id))
				assert.NoError(t, err)
			}(i)
		}
		wg.Wait()

		files, _ := fileHandler.GetFiles("concurrentBucket")
		assert.Equal(t, routines, len(files))
	})

}

func TestGetFiles(t *testing.T) {
	type args struct {
		bucket string
		files  map[string]bool
	}
	tests := []struct {
		name    string
		args    args
		want    map[string]bool
		wantErr assert.ErrorAssertionFunc
	}{
		{
			"Retrieve files from an existing bucket",
			args{
				bucket: "testBucket1",
				files: map[string]bool{
					"testFile1": true,
					"testFile2": true,
				},
			},
			map[string]bool{
				"testFile1": true,
				"testFile2": true,
			},
			assert.NoError,
		},
		{
			"Retrieve files from a non-existent bucket",
			args{
				bucket: "testBucket2",
				files:  nil,
			},
			map[string]bool{},
			assert.Error,
		},
	}

	fileHandler, _ := CreateInMemoryFileHandler()

	// Prepopulate fileHandler for the tests
	for _, tt := range tests {
		if tt.args.files != nil {
			err := fileHandler.AddFiles(tt.args.bucket, tt.args.files)
			assert.NoError(t, err)
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fileHandler.GetFiles(tt.args.bucket)

			if !tt.wantErr(t, err) {
				return
			}
			assert.Equalf(t, tt.want, got, "GetFiles(%v)", tt.args.bucket)
		})
	}

	t.Run("Race condition check for GetFiles", func(t *testing.T) {
		const routines = 1000
		wg := &sync.WaitGroup{}
		wg.Add(routines)

		// Create a bucket with multiple files
		files := make(map[string]bool)
		for i := 0; i < routines; i++ {
			files[fmt.Sprintf("testFile%d", i)] = true
		}

		for i := 0; i < routines; i++ {
			go func() {
				defer wg.Done()
				e := fileHandler.AddFiles("concurrentBucketGet", files)
				assert.NoError(t, e)
				_, err := fileHandler.GetFiles("concurrentBucketGet")
				assert.NoError(t, err)
			}()
		}
		wg.Wait()
	})
}

func TestAddFiles(t *testing.T) {
	type args struct {
		bucket string
		files  map[string]bool
	}
	tests := []struct {
		name    string
		args    args
		wantErr assert.ErrorAssertionFunc
	}{
		{
			"Add multiple files to an existing bucket",
			args{
				bucket: "testBucket1",
				files: map[string]bool{
					"testFile1": true,
					"testFile2": true,
				},
			},
			assert.NoError,
		},
		{
			"Add multiple files to a new bucket",
			args{
				bucket: "testBucket2",
				files: map[string]bool{
					"testFile3": true,
					"testFile4": true,
				},
			},
			assert.NoError,
		},
	}

	fileHandler, _ := CreateInMemoryFileHandler()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := fileHandler.AddFiles(tt.args.bucket, tt.args.files)
			tt.wantErr(t, err)
		})
	}

	t.Run("Race condition check for AddFiles", func(t *testing.T) {
		const routines = 1000
		wg := &sync.WaitGroup{}
		wg.Add(routines)

		// The idea here is to use separate buckets for each goroutine to ensure there's contention
		// on the main mutex that protects the buckets map.
		for i := 0; i < routines; i++ {
			go func(id int) {
				defer wg.Done()
				files := map[string]bool{
					fmt.Sprintf("testFile%d", id*2):   true,
					fmt.Sprintf("testFile%d", id*2+1): true,
				}
				err := fileHandler.AddFiles(fmt.Sprintf("concurrentBucket%d", id), files)
				assert.NoError(t, err)
			}(i)
		}
		wg.Wait()

		// After adding, let's check if all buckets have been created
		for i := 0; i < routines; i++ {
			_, err := fileHandler.GetFiles(fmt.Sprintf("concurrentBucket%d", i))
			assert.NoError(t, err)
		}
	})
}

func Test_RemoveBucket(t *testing.T) {
	type args struct {
		bucket string
	}
	tests := []struct {
		name    string
		args    args
		wantErr assert.ErrorAssertionFunc
		setup   func(handler *InMemoryFileHandler) // Optional setup function
	}{
		{
			"Remove an existing bucket",
			args{
				bucket: "testBucket1",
			},
			assert.NoError,
			func(handler *InMemoryFileHandler) {
				handler.AddFile("testBucket1", "testFile1")
			},
		},
		{
			"Remove a non-existent bucket",
			args{
				bucket: "testBucket2",
			},
			assert.NoError, // RemoveBucket doesn't error if bucket doesn't exist
			nil,
		},
	}

	fileHandler, _ := CreateInMemoryFileHandler()

	for _, tt := range tests {
		if tt.setup != nil {
			tt.setup(fileHandler)
		}

		t.Run(tt.name, func(t *testing.T) {
			err := fileHandler.RemoveBucket(tt.args.bucket)
			tt.wantErr(t, err)
		})
	}

	t.Run("Race condition check for RemoveBucket", func(t *testing.T) {
		const routines = 1000
		wg := &sync.WaitGroup{}
		wg.Add(routines)

		// Create buckets first
		for i := 0; i < routines; i++ {
			fileHandler.AddFile(fmt.Sprintf("concurrentBucket%d", i), fmt.Sprintf("testFile%d", i))
		}

		// Now, let's remove them concurrently
		for i := 0; i < routines; i++ {
			go func(id int) {
				defer wg.Done()
				err := fileHandler.RemoveBucket(fmt.Sprintf("concurrentBucket%d", id))
				assert.NoError(t, err)
			}(i)
		}
		wg.Wait()

		// After removal, let's check to ensure all buckets have been removed
		for i := 0; i < routines; i++ {
			_, err := fileHandler.GetFiles(fmt.Sprintf("concurrentBucket%d", i))
			assert.Error(t, err) // As buckets are removed, an error is expected when trying to retrieve files
		}
	})
}

func Test_shallowCopyMapStringBool(t *testing.T) {
	tests := []struct {
		name  string
		input map[string]bool
		want  map[string]bool
	}{
		{
			"Shallow copy of a non-empty map",
			map[string]bool{
				"test1": true,
				"test2": false,
			},
			map[string]bool{
				"test1": true,
				"test2": false,
			},
		},
		{
			"Shallow copy of an empty map",
			map[string]bool{},
			map[string]bool{},
		},
		{
			"Shallow copy of a nil map",
			nil,
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			copy := shallowCopyMapStringBool(tt.input)

			// Assert maps are equal
			assert.Equal(t, tt.want, copy)

			// If input map isn't nil, alter the copy and ensure original remains unchanged
			if tt.input != nil {
				copy["newKey"] = true
				assert.NotEqual(t, tt.input, copy)
			}
		})
	}
}
