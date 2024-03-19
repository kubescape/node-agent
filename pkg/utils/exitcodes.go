package utils

const (
	// standard exit codes
	ExitCodeSuccess = iota
	ExitCodeError   = 1

	// custom exit codes
	ExitCodeRuncNotFound       = 100
	ExitCodeIncompatibleKernel = 101
	ExitCodeMacOS              = 102
)
