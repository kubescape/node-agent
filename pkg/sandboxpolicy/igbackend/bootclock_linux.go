package igbackend

import "golang.org/x/sys/unix"

// bootClock is the time since boot in nanoseconds (CLOCK_BOOTTIME, suspend
// included). It orders the pinned sets of one boot (bpffs does not survive a
// reboot), and a wall clock step cannot reorder it. The call cannot fail on
// Linux for this clock.
func bootClock() int64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts)
	return ts.Nano()
}
