package igbackend

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

// enumNames lists the members of a C enum in order, lower case, without
// prefix.
func enumNames(t *testing.T, file, enum, prefix string) []string {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	start := strings.Index(src, "enum "+enum+" ")
	if start < 0 {
		t.Fatalf("no enum %s in %s", enum, file)
	}
	body := src[start:]
	body = body[strings.Index(body, "{")+1 : strings.Index(body, "};")]
	var names []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		name := strings.TrimPrefix(line, prefix)
		if i := strings.IndexAny(name, " =,"); i >= 0 {
			name = name[:i]
		}
		names = append(names, strings.ToLower(name))
	}
	return names
}

// The summary name tables follow the gadgets' enums, in order.
func TestSummaryNamesMatchEnums(t *testing.T) {
	g := "../../ebpf/gadgets/"
	for _, c := range []struct {
		file, enum, prefix string
		names              []string
	}{
		{g + "enforce_privilege/program.bpf.c", "priv_hook", "PRIV_HOOK_", privHookNames},
		{g + "enforce_privilege/program.bpf.c", "priv_syscall", "PRIV_SC_", privSyscallNames},
		{g + "enforce_file/program.bpf.c", "file_hook", "FILE_HOOK_", fileHookNames},
		{g + "enforce_file/file_policy.h", "file_access", "FILE_ACCESS_", fileAccessNames},
		{g + "enforce_network/program.bpf.c", "net_hook", "NET_HOOK_", netHookNames},
	} {
		if got := enumNames(t, c.file, c.enum, c.prefix); !reflect.DeepEqual(got, c.names) {
			t.Errorf("%s: table %v, enum %v", c.enum, c.names, got)
		}
	}
	for _, c := range []struct {
		section      string
		hook, detail uint32
		wantHook     string
		wantDetail   string
	}{
		{"privilege", 2, 7, "capable", "CAP_SETUID"},
		{"privilege", 2, 21 | 1<<8, "capable", "CAP_SYS_ADMIN syscall unshare"},
		{"privilege", 0, 0xff | 5<<8, "userns_create", "syscall mount"},
		{"privilege", 99, 77, "hook 99", "capability 77"},
		{"file", 0, 1, "file_open", "write"},
		{"network", 1, 0, "socket_sendmsg", ""},
	} {
		if h, d := summaryNames(c.section, c.hook, c.detail); h != c.wantHook || d != c.wantDetail {
			t.Errorf("%+v: %q %q", c, h, d)
		}
	}
}
