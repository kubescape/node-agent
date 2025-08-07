package tracers

import (
	"fmt"
	"time"
)

// Example usage of the PathResolver component
func ExamplePathResolverUsage() {
	// Create a new path resolver with default settings (10k cache size, 1 hour expiration)
	resolver := NewPathResolver()

	// Or create with custom settings
	customResolver := NewPathResolverWithConfig(5000, 30*time.Minute)

	// Example 1: Resolve a relative path for a specific PID
	pid := uint32(1234)
	relativePath := "config/app.conf"

	fullPath, err := resolver.ResolvePath(pid, relativePath)
	if err != nil {
		fmt.Printf("Error resolving path: %v\n", err)
		return
	}
	fmt.Printf("Resolved path: %s\n", fullPath)

	// Example 2: Resolve an absolute path (returns as-is)
	absolutePath := "/usr/bin/ls"
	fullPath, err = resolver.ResolvePath(pid, absolutePath)
	if err != nil {
		fmt.Printf("Error resolving path: %v\n", err)
		return
	}
	fmt.Printf("Absolute path: %s\n", fullPath)

	// Example 3: Cache functionality
	// First call - resolves from procfs
	path1, _ := resolver.ResolvePath(pid, "data/file.txt")
	fmt.Printf("First call result: %s\n", path1)

	// Second call - uses cache
	path2, _ := resolver.ResolvePath(pid, "data/file.txt")
	fmt.Printf("Second call result: %s\n", path2)
	fmt.Printf("Cache size: %d\n", resolver.GetCacheSize())

	// Example 4: Clear cache
	resolver.ClearCache()
	fmt.Printf("After clearing cache: %d\n", resolver.GetCacheSize())

	// Example 5: Using with custom resolver
	customPath, err := customResolver.ResolvePath(pid, "logs/app.log")
	if err != nil {
		fmt.Printf("Error with custom resolver: %v\n", err)
		return
	}
	fmt.Printf("Custom resolver result: %s\n", customPath)
}

// Example of integrating with OpenTracer
func ExampleOpenTracerIntegration() {
	// This shows how you could modify the existing OpenTracer to use PathResolver

	// In the OpenTracer struct, add:
	// pathResolver *PathResolver

	// In the constructor:
	// pathResolver: NewPathResolver(),

	// In the event callback:
	/*
		func (ot *OpenTracer) openEventCallback(event *traceropentype.Event) {
			// ... existing validation code ...

			if event.Err > -1 && event.Path != "" {
				// Use path resolver when full path tracing is disabled
				if !ot.cfg.EnableFullPathTracing {
					fullPath, err := ot.pathResolver.ResolvePath(event.Pid, event.Path)
					if err != nil {
						// Log error but continue with original path
						event.FullPath = event.Path
					} else {
						event.FullPath = fullPath
					}
				} else {
					event.FullPath = event.Path
				}

				// ... continue with event processing ...
			}
		}
	*/
}
