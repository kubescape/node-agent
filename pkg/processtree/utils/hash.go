package utils

import (
	"crypto/md5"
	"encoding/binary"
)

// HashTaskID creates a unique hash for a process based on PID and start time
// This prevents PID reuse issues by making each process instance unique
func HashTaskID(pid uint32, startTimeNs uint64) uint32 {
	// Create a buffer with PID (4 bytes) + start time (8 bytes)
	buffer := make([]byte, 12)
	binary.BigEndian.PutUint32(buffer[:4], pid)
	binary.BigEndian.PutUint64(buffer[4:], startTimeNs)

	// Use MD5 and take first 4 bytes as uint32
	hash := md5.Sum(buffer)
	return binary.BigEndian.Uint32(hash[:4])
}
