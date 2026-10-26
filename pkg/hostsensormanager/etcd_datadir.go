package hostsensormanager

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"strings"

	"sigs.k8s.io/yaml"
)

// etcdDataDir returns the data directory an etcd process uses, as a path in the
// process's own filesystem, following etcd's configuration precedence:
//
//  1. A configuration file (--config-file or ETCD_CONFIG_FILE). etcd then ignores
//     every other flag and environment variable.
//  2. The --data-dir flag, which shadows ETCD_DATA_DIR.
//  3. ETCD_DATA_DIR (OpenShift configures etcd this way).
//  4. The default, "<name>.etcd", with the name from --name or ETCD_NAME ("default").
//
// Relative paths are resolved against the process's working directory.
func etcdDataDir(proc *ProcessDetails) (string, error) {
	procDir := hostPath(path.Join(procDirName, fmt.Sprint(proc.PID)))
	env := processEnviron(path.Join(procDir, "environ"))
	resolve := func(p string) (string, error) {
		if path.IsAbs(p) {
			return path.Clean(p), nil
		}
		cwd, err := os.Readlink(path.Join(procDir, "cwd"))
		if err != nil {
			return "", fmt.Errorf("resolve %q against the etcd working directory: %w", p, err)
		}
		return path.Join(cwd, p), nil
	}
	setting := func(flag, variable string) string {
		if value, ok := etcdFlag(proc, flag); ok && value != "" {
			return value
		}
		return env[variable]
	}

	name, dir := setting("name", "ETCD_NAME"), setting("data-dir", "ETCD_DATA_DIR")
	if configFile := setting("config-file", "ETCD_CONFIG_FILE"); configFile != "" {
		file, err := resolve(configFile)
		if err != nil {
			return "", err
		}
		content, err := os.ReadFile(path.Join(proc.RootDir(), file))
		if err != nil {
			return "", fmt.Errorf("read the etcd configuration file: %w", err)
		}
		var config struct {
			Name    string `json:"name"`
			DataDir string `json:"data-dir"`
		}
		if err := yaml.Unmarshal(content, &config); err != nil {
			return "", fmt.Errorf("parse the etcd configuration file %s: %w", file, err)
		}
		name, dir = config.Name, config.DataDir
	}
	if dir == "" {
		if name == "" {
			name = "default"
		}
		dir = name + ".etcd"
	}
	return resolve(dir)
}

// etcdFlag reads an etcd flag, which Go's flag package accepts with one or two dashes.
func etcdFlag(proc *ProcessDetails, name string) (string, bool) {
	for _, prefix := range []string{"--", "-"} {
		if value, ok := proc.GetArg(prefix + name); ok {
			return value, true
		}
	}
	return "", false
}

// processEnviron reads a /proc/<pid>/environ file; it is empty when unreadable.
func processEnviron(file string) map[string]string {
	env := map[string]string{}
	content, err := os.ReadFile(file)
	if err != nil {
		return env
	}
	for _, entry := range bytes.Split(content, []byte{0}) {
		if key, value, ok := strings.Cut(string(entry), "="); ok {
			env[key] = value
		}
	}
	return env
}
