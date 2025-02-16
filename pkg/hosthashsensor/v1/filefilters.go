package hosthashsensor

import (
	"path/filepath"
	"slices"
)

type SimpleFileFilter struct {
}

func fileExtensionIsSoftwareComponent(path string) bool {
	// List all file extensions that are considered software components (including interpreted languages)
	softwareComponentExtensions := []string{
		".so", ".dll", ".dylib", ".lib",
		".py", ".rb", ".php", ".js", ".ts", ".jsx", ".tsx", ".css", ".html", ".toml", ".lock", ".lockb", ".lockt", ".lockc", ".lockd", ".locke", ".lockf", ".lockg", ".lockh", ".locki", ".lockj", ".lockk", ".lockl", ".lockm", ".lockn", ".locko", ".lockp", ".lockq", ".lockr", ".locks", ".lockt", ".locku", ".lockv", ".lockw", ".lockx", ".locky", ".lockz",
		".java", ".jar",
	}
	return slices.Contains(softwareComponentExtensions, filepath.Ext(path))
}

func (f *SimpleFileFilter) ShouldTrack(path string, accessType FileAccessType) bool {
	if accessType == FileAccessTypeExec {
		return true
	}
	if accessType == FileAccessTypeOpenRead {
		return fileExtensionIsSoftwareComponent(path)
	}
	return false
}
