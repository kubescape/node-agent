package utils

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/syscalls"
)

func decodeSyscalls(syscallsBuffer []byte) []string {
	syscallStrings := make([]string, 0)
	for i := range syscallsBuffer {
		if syscallsBuffer[i] > 0 {
			syscallName, exist := syscalls.GetSyscallNameByNumber(i)
			if !exist {
				syscallName = "unknown"
			}
			syscallStrings = append(syscallStrings, syscallName)
		}
	}
	return syscallStrings
}
