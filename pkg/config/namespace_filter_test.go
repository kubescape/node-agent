package config

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestNamespaceFilterReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "filter.json")
	write := func(data string) { t.Helper(); require.NoError(t, os.WriteFile(path, []byte(data), 0600)) }
	write(`{"includeNamespaces":["payments"],"excludeNamespaces":["payments"]}`)
	cfg := Config{NamespaceFilterFile: path, ExcludeNamespaces: []string{"payments"}}
	require.NoError(t, cfg.InitializeNamespaceFilter())
	copied := cfg
	require.False(t, copied.SkipNamespace("payments"), "include takes precedence")
	require.True(t, copied.SkipNamespace("default"))
	write(`{"includeNamespaces":[],"excludeNamespaces":["payments"]}`)
	changed, err := cfg.ReloadNamespaceFilter()
	require.NoError(t, err)
	require.True(t, changed)
	require.True(t, copied.SkipNamespace("payments"), "copies share updates")
	require.False(t, copied.SkipNamespace("default"))
	changed, err = cfg.ReloadNamespaceFilter()
	require.NoError(t, err)
	require.False(t, changed)
	for _, invalid := range []string{
		`{`, `{}`, `null`, `[]`, `{"includeNamespaces":[],"excludeNamespaces":null}`,
		`{"includeNamespaces":[],"excludeNamespaces":"payments"}`,
		`{"includeNamespaces":[],"excludeNamespaces":["Bad_Name"]}`,
		`{"includeNamespaces":[],"excludeNamespaces":[null]}`,
		`{"includeNamespaces":[],"excludeNamespaces":[],"typo":true}`,
		`{"includeNamespaces":[],"excludeNamespaces":[]} {}`,
	} {
		write(invalid)
		changed, err = cfg.ReloadNamespaceFilter()
		require.Error(t, err, invalid)
		require.False(t, changed)
		require.True(t, copied.SkipNamespace("payments"), "invalid update retains last valid filter")
	}
	require.NoError(t, os.Remove(path))
	_, err = cfg.ReloadNamespaceFilter()
	require.Error(t, err)
	require.True(t, copied.SkipNamespace("payments"))
	write(`{"includeNamespaces":[],"excludeNamespaces":[]}`)
	_, err = cfg.ReloadNamespaceFilter()
	require.NoError(t, err)
	require.False(t, copied.SkipNamespace("payments"), "empty arrays clear filters")
}

func TestNamespaceFilterProjectedVolume(t *testing.T) {
	dir := t.TempDir()
	for name, contents := range map[string]string{
		"v1": `{"includeNamespaces":["one"],"excludeNamespaces":[]}`,
		"v2": `{"includeNamespaces":["two"],"excludeNamespaces":[]}`,
	} {
		require.NoError(t, os.Mkdir(filepath.Join(dir, name), 0700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, name, "filter.json"), []byte(contents), 0600))
	}
	require.NoError(t, os.Symlink("v1", filepath.Join(dir, "..data")))
	require.NoError(t, os.Symlink("..data/filter.json", filepath.Join(dir, "filter.json")))
	cfg := Config{NamespaceFilterFile: filepath.Join(dir, "filter.json")}
	require.NoError(t, cfg.InitializeNamespaceFilter())
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 10000 {
				cfg.SkipNamespace("one")
				cfg.SkipNamespace("two")
			}
		})
	}
	require.NoError(t, os.Symlink("v2", filepath.Join(dir, "..data_tmp")))
	require.NoError(t, os.Rename(filepath.Join(dir, "..data_tmp"), filepath.Join(dir, "..data")))
	changed, err := cfg.ReloadNamespaceFilter()
	require.NoError(t, err)
	require.True(t, changed)
	wg.Wait()
	require.True(t, cfg.SkipNamespace("one"))
	require.False(t, cfg.SkipNamespace("two"))
}

func TestNamespaceFilterOptIn(t *testing.T) {
	cfg := Config{ExcludeNamespaces: []string{"payments"}}
	require.NoError(t, cfg.InitializeNamespaceFilter())
	changed, err := cfg.ReloadNamespaceFilter()
	require.NoError(t, err)
	require.False(t, changed)
	require.True(t, cfg.SkipNamespace("payments"))
	cfg.NamespaceFilterFile = filepath.Join(t.TempDir(), "missing")
	require.Error(t, cfg.InitializeNamespaceFilter())
}

func TestNamespaceFilterUnionExclusions(t *testing.T) {
	filters := []*NamespaceFilter{
		{}, {include: []string{"one"}}, {include: []string{"two"}},
		{include: []string{"one", "two"}, exclude: []string{"one"}},
		{exclude: []string{"one"}}, {exclude: []string{"two"}}, {excludeAll: true},
	}
	for _, first := range filters {
		for _, second := range filters {
			merged := first.UnionExclusions(second)
			for _, namespace := range []string{"one", "two", "three"} {
				require.Equal(t, first.SkipNamespace(namespace) || second.SkipNamespace(namespace), merged.SkipNamespace(namespace))
			}
		}
	}
}

func TestLoadConfigNamespaceFilterFile(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	dir := t.TempDir()
	path := filepath.Join(dir, "filter.json")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"excludeNamespaces":["default"]}`), 0600))
	t.Setenv("NAMESPACEFILTERFILE", path)
	_, err := LoadConfig(dir)
	require.Error(t, err, "an explicit missing file must fail startup")
	require.NoError(t, os.WriteFile(path, []byte(`{"includeNamespaces":["default"],"excludeNamespaces":[]}`), 0600))
	cfg, err := LoadConfig(dir)
	require.NoError(t, err)
	require.Equal(t, path, cfg.NamespaceFilterFile)
	require.False(t, cfg.SkipNamespace("default"), "file overrides static filters")
	require.True(t, cfg.SkipNamespace("payments"))
}
