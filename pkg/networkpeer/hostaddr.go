package networkpeer

import (
	"bufio"
	"net"
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// Node-sourced traffic arrives from a node address the CNI chooses; scoped to the LOCAL node so cross-node traffic still alerts.

// One source among several: present only when the CNI annotates the Node.
const ciliumHostAnnotation = "io.cilium.network.ipv4-cilium-host"

// PID 1's view, not /proc/net: that is a symlink through self and would resolve to the agent's own netns.
var hostProcNetRoot = "/host/proc/1/net"

// nodeAnnotatedRouterIPs returns router addresses a CNI published on the Node.
func nodeAnnotatedRouterIPs(n *corev1.Node) []string {
	if n == nil {
		return nil
	}
	var out []string
	for _, key := range []string{ciliumHostAnnotation} {
		if v, ok := n.Annotations[key]; ok {
			for _, candidate := range strings.Split(v, ",") {
				candidate = strings.TrimSpace(candidate)
				if ip := net.ParseIP(candidate); ip != nil {
					out = append(out, ip.String())
				}
			}
		}
	}
	return out
}

// localHostIPv4s reads the node's own addresses from the kernel's LOCAL table: every CNI's router interface, without knowing which CNI.
func localHostIPv4s() []string {
	f, err := os.Open(hostProcNetRoot + "/fib_trie")
	if err != nil {
		return nil
	}
	defer f.Close()

	seen := map[string]struct{}{}
	var out []string
	inLocal := false
	var pending string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "Main:"):
			inLocal = false
			continue
		case strings.HasPrefix(trimmed, "Local:"):
			inLocal = true
			continue
		}
		if !inLocal {
			continue
		}
		// A leaf line carries the address, the line after it carries its type.
		if idx := strings.Index(trimmed, "|--"); idx >= 0 {
			pending = strings.TrimSpace(trimmed[idx+3:])
			continue
		}
		if pending == "" || !strings.Contains(trimmed, "/32") {
			continue
		}
		if !strings.Contains(trimmed, "LOCAL") {
			pending = ""
			continue
		}
		ip := net.ParseIP(pending)
		pending = ""
		if ip == nil || ip.To4() == nil || ip.IsLoopback() {
			continue
		}
		s := ip.String()
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
