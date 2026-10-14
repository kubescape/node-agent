package httpcapture

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

// Compile the port expressions from the actual gadget, using Linux's
// socket ABI (skc_num host endian, skc_dport network endian). This verifies the
// production source as well as the reported 8080/8000 examples, without loading BPF.
func TestHTTPGadgetSocketPortByteOrder(t *testing.T) {
	dir := t.TempDir()
	source, err := os.ReadFile("../program.bpf.c")
	require.NoError(t, err)
	local := regexp.MustCompile(`__u16 local_port = [^;]+;`).Find(source)
	remote := regexp.MustCompile(`__u16 remote_port = [^;]+;`).Find(source)
	require.NotEmpty(t, local)
	require.NotEmpty(t, remote)
	harness := fmt.Sprintf(`#include <stdint.h>
#include <arpa/inet.h>
#include <assert.h>
typedef uint16_t __u16;
#define BPF_CORE_READ(sk, field) ((sk)->field)
#define bpf_ntohs(port) ntohs(port)
struct sock { struct { __u16 skc_num, skc_dport; } __sk_common; };
int main(void) {
    const __u16 ports[] = {8080, 8000, 443, 80, 1, 65535};
    for (unsigned i = 0; i < sizeof(ports)/sizeof(ports[0]); i++) {
        struct sock socket = {. __sk_common = {ports[i], htons(12345)}};
        struct sock *sk = &socket;
        %s
        %s
        assert(local_port == ports[i]);
        assert(remote_port == 12345);
    }
    return 0;
}
`, local, remote)
	cFile := filepath.Join(dir, "ports.c")
	require.NoError(t, os.WriteFile(cFile, []byte(harness), 0o600))
	binary := filepath.Join(dir, "ports")
	out, err := exec.Command("cc", "-Wall", "-Werror", cFile, "-o", binary).CombinedOutput()
	require.NoError(t, err, "%s", out)
	out, err = exec.Command(binary).CombinedOutput()
	require.NoError(t, err, "%s", out)
}
