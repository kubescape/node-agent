package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

func main() {
	// If the environment variable WAIT_BEFORE_START is set, wait for X seconds
	// before starting
	if os.Getenv("WAIT_BEFORE_START") != "" {
		// Wait for X seconds (X is the value of the WAIT_BEFORE_START environment variable)
		if waitBeforeStart, err := time.ParseDuration(os.Getenv("WAIT_BEFORE_START")); err == nil {
			time.Sleep(waitBeforeStart)
		}
	}

	// Run all malicious behaviors
	runAllMaliciousBehaviors()

	// If the environment variable WAIT_FOR_SIGTERM is set, wait for SIGTERM
	// before exiting
	if os.Getenv("WAIT_FOR_SIGTERM") != "" {
		// Wait for SIGTERM
		sigterm := make(chan os.Signal, 1)
		signal.Notify(sigterm, syscall.SIGTERM)
		<-sigterm
	}
}

func runAllMaliciousBehaviors() error {
	fmt.Println("Running malicious behaviors...")

	// ------------------------------------------------------------------
	// R0001 - Unexpected process launched (exec not in baseline)
	// R1001 - Drifted process executed (binary not in base image, upperlayer=true)
	// R0007 - Workload uses Kubernetes API unexpectedly (kubectl exec + API network)
	// ------------------------------------------------------------------
	err := downloadKubectl()
	if err != nil {
		fmt.Printf("Failed to download kubectl: %v\n", err)
		return err
	}
	fmt.Println("[R0001/R1001/R0007] Running kubectl get secrets...")
	output, err := runKubectl("./kubectl", "get", "secrets")
	if err != nil {
		fmt.Printf("kubectl failed (expected): %v\n", err)
	}
	fmt.Print(output)

	// ------------------------------------------------------------------
	// R0006 - Unexpected service account token access
	// ------------------------------------------------------------------
	fmt.Println("[R0006] Opening service account token file...")
	file, err := os.Open("/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		fmt.Printf("Failed to open SA token: %v\n", err)
	} else {
		file.Close()
	}

	// ------------------------------------------------------------------
	// R0002 - Files Access Anomalies in container (file under monitored path)
	// ------------------------------------------------------------------
	fmt.Println("[R0002] Opening malicious.txt for writing...")
	file, err = os.OpenFile("malicious.txt", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Failed to open file: %v\n", err)
	} else {
		file.WriteString("This is a malicious file\n")
		file.Close()
	}

	// ------------------------------------------------------------------
	// R0008 - Read Environment Variables from procfs
	// ------------------------------------------------------------------
	fmt.Println("[R0008] Reading /proc/self/environ...")
	envData, err := os.ReadFile("/proc/self/environ")
	if err != nil {
		fmt.Printf("Failed to read /proc/self/environ: %v\n", err)
	} else {
		fmt.Printf("Read %d bytes from /proc/self/environ\n", len(envData))
	}

	// ------------------------------------------------------------------
	// R0010 - Unexpected Sensitive File Access (/etc/shadow)
	// ------------------------------------------------------------------
	fmt.Println("[R0010] Reading /etc/shadow...")
	file, err = os.Open("/etc/shadow")
	if err != nil {
		fmt.Printf("Failed to open /etc/shadow (expected in distroless): %v\n", err)
	} else {
		file.Close()
	}

	// ------------------------------------------------------------------
	// R0005 - DNS Anomalies in container (domain not in network neighborhood)
	// ------------------------------------------------------------------
	fmt.Println("[R0005] Making HTTP request to google.com...")
	_, err = http.Get("https://www.google.com")
	if err != nil {
		fmt.Printf("Failed to make HTTP request: %v\n", err)
	}

	// ------------------------------------------------------------------
	// R0003 - Syscalls Anomalies in container (unshare not in baseline)
	// R1006 - Process tries to escape container (unshare from non-runc parent)
	// ------------------------------------------------------------------
	fmt.Println("[R0003/R1006] Calling SYS_UNSHARE with CLONE_NEWUSER...")
	_, _, err = syscall.Syscall(syscall.SYS_UNSHARE, syscall.CLONE_NEWUSER, 0, 0)
	if err != nil {
		fmt.Printf("SYS_UNSHARE failed (expected): %v\n", err)
	}

	// ------------------------------------------------------------------
	// R0004 - Linux Capabilities Anomalies in container
	// ------------------------------------------------------------------
	fmt.Println("[R0004] Binding to privileged port 80...")
	listener, err := net.Listen("tcp", ":80")
	if err != nil {
		fmt.Printf("Failed to bind to port 80: %v\n", err)
	} else {
		listener.Close()
	}

	// ------------------------------------------------------------------
	// R1000 - Process executed from malicious source (/dev/shm)
	// ------------------------------------------------------------------
	fmt.Println("[R1000] Creating symbolic link to ls in /dev/shm...")
	os.Remove("/dev/shm/ls")
	err = os.Symlink("/bin/ls", "/dev/shm/ls")
	if err != nil {
		fmt.Printf("Failed to create symlink in /dev/shm: %v\n", err)
		return err
	}
	fmt.Println("[R1000] Executing ls from /dev/shm...")
	cmd := exec.Command("/dev/shm/ls")
	cmdoutput, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Failed to execute from /dev/shm: %v\n", err)
		// Fallback via sh
		cmd = exec.Command("sh", "-c", "cd /dev/shm && ./ls")
		cmdoutput, err = cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("Fallback also failed: %v\n", err)
		} else {
			fmt.Println(string(cmdoutput))
		}
	} else {
		fmt.Println(string(cmdoutput))
	}
	os.Remove("/dev/shm/ls")

	// ------------------------------------------------------------------
	// R1002 - Process tries to load a kernel module (SYS_INIT_MODULE)
	// ------------------------------------------------------------------
	fmt.Println("[R1002] Calling SYS_INIT_MODULE...")
	_, _, err = syscall.Syscall(syscall.SYS_INIT_MODULE, 0, 0, 0)
	if err != nil {
		fmt.Printf("SYS_INIT_MODULE failed (expected): %v\n", err)
	}

	// ------------------------------------------------------------------
	// R1004 - Process executed from mount (exec from emptyDir volume)
	// ------------------------------------------------------------------
	fmt.Println("[R1004] Copying kubectl to /podmount and executing...")
	err = copyFile("kubectl", "/podmount/kubectl")
	if err != nil {
		fmt.Printf("Failed to copy kubectl to /podmount: %v\n", err)
	} else {
		out, err := runKubectl("/podmount/kubectl", "get", "secrets")
		if err != nil {
			fmt.Printf("kubectl on /podmount failed (expected): %v\n", err)
		}
		if out != "" {
			fmt.Print(out)
		}
	}

	// ------------------------------------------------------------------
	// R1015 - Malicious Ptrace Usage (ptrace syscall)
	// ------------------------------------------------------------------
	fmt.Println("[R1015] Calling SYS_PTRACE (PTRACE_TRACEME)...")
	_, _, err = syscall.Syscall(syscall.SYS_PTRACE, 0 /* PTRACE_TRACEME */, 0, 0)
	if err != nil {
		fmt.Printf("SYS_PTRACE failed (expected): %v\n", err)
	}

	// ------------------------------------------------------------------
	// R1008 - Crypto Mining Domain Communication (DNS for known mining domain)
	// R1009 - Crypto Mining Related Port Communication (TCP to port 45700)
	// ------------------------------------------------------------------
	fmt.Println("[R1008/R1009] Connecting to xmr.pool.minergate.com:45700...")
	conn, err := net.Dial("tcp", "xmr.pool.minergate.com:45700")
	if err != nil {
		fmt.Printf("Failed to connect to mining pool: %v\n", err)
	} else {
		conn.Close()
	}

	return nil
}

// downloadFile downloads a file from the specified URL and saves it to the given filepath.
func downloadFile(filepath string, url string) error {
	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to download file: %s", resp.Status)
	}

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	return nil
}

// downloadKubectl downloads the latest kubectl binary for the current platform.
func downloadKubectl() error {
	// Determine the OS and Architecture
	osName := runtime.GOOS
	arch := runtime.GOARCH

	fmt.Print("Downloading kubectl\n")

	url := fmt.Sprintf("https://dl.k8s.io/release/v1.32.0/bin/%s/%s/kubectl", osName, arch)

	// Print the URL
	fmt.Printf("Downloading kubectl from %s...\n", url)

	// Download the file
	err := downloadFile("kubectl", url)
	if err != nil {
		return err
	}

	// Make the kubectl binary executable
	err = os.Chmod("kubectl", 0755)
	if err != nil {
		return err
	}

	fmt.Println("kubectl downloaded successfully.")
	return nil
}

func runKubectl(path string, args ...string) (string, error) {
	// Create an *exec.Cmd
	cmd := exec.Command(path, args...)

	// Capture the output
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	// Run the command
	err := cmd.Run()
	if err != nil {
		return out.String(), err
	}

	return out.String(), nil
}

func copyFile(src, dst string) error {
	// Open the source file for reading
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	// Create the destination file for writing
	destinationFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destinationFile.Close()

	// Copy the contents of the source file to the destination file
	_, err = io.Copy(destinationFile, sourceFile)
	if err != nil {
		return err
	}

	// Copy file permissions from source to destination
	sourceInfo, err := os.Stat(src)
	if err != nil {
		return err
	}
	err = os.Chmod(dst, sourceInfo.Mode())
	if err != nil {
		return err
	}

	return nil
}
