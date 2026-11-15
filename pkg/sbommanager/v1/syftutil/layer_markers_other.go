//go:build !linux

package syftutil

// Overlay layer directories only exist on Linux nodes.

func isWhiteoutDevice(string) bool { return false }

func isOpaqueDir(string) bool { return false }
