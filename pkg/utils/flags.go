package utils

import "math/bits"

// copied from https://github.com/inspektor-gadget/inspektor-gadget/blob/bd97419d4038dacda30255779243c48bc450e745/pkg/operators/formatters/formatters.go

// Standard Linux file open flags from <fcntl.h>
const (
	// Access modes (handled separately)
	O_RDONLY  = 0
	O_WRONLY  = 1
	O_RDWR    = 2
	O_ACCMODE = 3

	// Bit flags
	O_CREAT     = 0o100
	O_EXCL      = 0o200
	O_NOCTTY    = 0o400
	O_TRUNC     = 0o1000
	O_APPEND    = 0o2000
	O_NONBLOCK  = 0o4000
	O_DSYNC     = 0o10000
	O_FASYNC    = 0o20000
	O_DIRECT    = 0o40000
	O_LARGEFILE = 0o100000
	O_DIRECTORY = 0o200000
	O_NOFOLLOW  = 0o400000
	O_NOATIME   = 0o1000000
	O_CLOEXEC   = 0o2000000
)

// flagMap pairs the bitmask of a flag with its string representation.
// Using a slice of structs makes the relationship explicit and order-independent.
var flagMap = []struct {
	val  int32
	name string
}{
	{O_CREAT, "O_CREAT"},
	{O_EXCL, "O_EXCL"},
	{O_NOCTTY, "O_NOCTTY"},
	{O_TRUNC, "O_TRUNC"},
	{O_APPEND, "O_APPEND"},
	{O_NONBLOCK, "O_NONBLOCK"},
	{O_DSYNC, "O_DSYNC"},
	{O_FASYNC, "O_FASYNC"},
	{O_DIRECT, "O_DIRECT"},
	{O_LARGEFILE, "O_LARGEFILE"},
	{O_DIRECTORY, "O_DIRECTORY"},
	{O_NOFOLLOW, "O_NOFOLLOW"},
	{O_NOATIME, "O_NOATIME"},
	{O_CLOEXEC, "O_CLOEXEC"},
}

func decodeFlags(flags int32) []string {
	// Pre-allocate a slice with a reasonable capacity to avoid reallocations.
	// The number of set bits gives an exact count.
	capacity := bits.OnesCount32(uint32(flags))
	out := make([]string, 0, capacity)

	// Handle the access mode, which is not a bitmask.
	switch flags & O_ACCMODE {
	case O_RDONLY:
		out = append(out, "O_RDONLY")
	case O_WRONLY:
		out = append(out, "O_WRONLY")
	case O_RDWR:
		out = append(out, "O_RDWR")
	}

	// Check each flag by its actual value.
	for _, f := range flagMap {
		if (flags & f.val) == f.val {
			out = append(out, f.name)
		}
	}

	return out
}
