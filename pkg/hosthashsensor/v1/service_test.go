package hosthashsensor

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/utils"
)

func Test_calculateHash(t *testing.T) {

	// Create a temporary file with 10MB of content
	f, err := os.CreateTemp("", "test-hash-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()

	numberOfMbs := 10

	// Write 10MB of random data
	data := make([]byte, numberOfMbs*1024*1024) // 10MB
	for i := range data {
		data[i] = byte(i % 256)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}

	service := &HostHashSensorService{}

	hashRequest := HashRequest{
		md5:    false,
		sha1:   false,
		sha256: true,
	}

	start := time.Now()
	hashes, err := service.calculateHash(f.Name(), hashRequest)
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)

	fmt.Printf("calculateHash took %dns\n", elapsed.Nanoseconds())
	//fmt.Println(hashes)
	// Calculate MB/s
	mbPerSec := (float64(numberOfMbs) * 1000000000.0 / float64(elapsed.Nanoseconds()))

	fmt.Printf("Speed: %.2f MB/s (%.2f GB/s)\n", mbPerSec, mbPerSec/1024)

	if hashRequest.md5 {
		// Verify hash against system md5 command
		cmd := exec.Command("md5sum", f.Name())
		output, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}

		// Parse md5 output - format is "hash\x20\x20filename"
		parts := strings.Split(string(output), "  ")
		if len(parts) != 2 {
			t.Fatal("Unexpected md5 command output format", string(output))
		}
		systemHash := strings.TrimSpace(parts[0])

		if systemHash != hashes.md5 {
			t.Errorf("Hash mismatch - system md5: %s, calculated: %s", systemHash, hashes.md5)
		}
	}

	if hashRequest.sha1 {
		// Verify hash against system sha1 command
		cmd := exec.Command("sha1sum", f.Name())
		output, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}

		// Parse sha1 output - format is "hash\x20\x20filename"
		parts := strings.Split(string(output), "  ")
		if len(parts) != 2 {
			t.Fatal("Unexpected sha1 command output format", string(output))
		}
		systemHash := strings.TrimSpace(parts[0])

		if systemHash != hashes.sha1 {
			t.Errorf("Hash mismatch - system sha1: %s, calculated: %s", systemHash, hashes.sha1)
		}

	}

	if hashRequest.sha256 {
		// Verify hash against system sha256 command
		cmd := exec.Command("sha256sum", f.Name())
		output, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}

		// Parse sha256 output - format is "hash\x20\x20filename"
		parts := strings.Split(string(output), "  ")
		if len(parts) != 2 {
			t.Fatal("Unexpected sha256 command output format", string(output))
		}
		systemHash := strings.TrimSpace(parts[0])

		if systemHash != hashes.sha256 {
			t.Errorf("Hash mismatch - system sha256: %s, calculated: %s", systemHash, hashes.sha256)
		}
	}

}

func Test_utils_CalculateFileHashes(t *testing.T) {
	// Create a temporary file with 10MB of content
	f, err := os.CreateTemp("", "test-hash-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()

	numberOfMbs := 10

	// Write 10MB of random data
	data := make([]byte, numberOfMbs*1024*1024) // 10MB
	for i := range data {
		data[i] = byte(i % 256)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	md5Hash, sha1Hash, err := utils.CalculateFileHashes(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)

	fmt.Printf("calculateHash took %dns\n", elapsed.Nanoseconds())
	//fmt.Println(hashes)
	// Calculate MB/s
	mbPerSec := (float64(numberOfMbs) * 1000000000.0 / float64(elapsed.Nanoseconds()))

	fmt.Printf("Speed: %.2f MB/s (%.2f GB/s)\n", mbPerSec, mbPerSec/1024)

	fmt.Println(md5Hash, sha1Hash)
}
