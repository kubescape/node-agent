package processtreecreator

import "golang.org/x/sys/unix"

// readBootTimeNs returns CLOCK_BOOTTIME now, in nanoseconds since boot.
//
// This is deliberately the same clock domain as the pidStartTimeNs side map,
// which holds /proc/<pid>/stat field 22 converted to nanoseconds. Timestamping
// exit arrivals on this clock lets the delayed-deletion guard compare
// boot-relative against boot-relative, with no btime skew and no wall-clock
// margin heuristic. Never substitute time.Now() here: that is a different clock
// domain, and the comparison would be meaningless rather than merely imprecise.
//
// A failed read returns 0, which every consumer treats as "unknown" and which
// makes the guard fall through to today's unconditional deletion.
func readBootTimeNs() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0
	}

	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}
