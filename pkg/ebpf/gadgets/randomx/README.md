# RandomX Gadget

This gadget traces RandomX mining activity by monitoring x86 FPU register deactivation events and detecting specific FPU control register patterns that are characteristic of RandomX mining operations.

## Description

RandomX is a proof-of-work algorithm used by Monero cryptocurrency. This gadget detects RandomX mining by monitoring the `x86_fpu_regs_deactivated` tracepoint and analyzing the FPU control register (FPCR) values. When specific patterns are detected in the MXCSR register, it indicates potential RandomX mining activity.

## How it works

1. **Tracepoint Monitoring**: The gadget hooks into the `x86_fpu/x86_fpu_regs_deactivated` tracepoint
2. **FPU Analysis**: It reads the MXCSR register from the FPU state
3. **Pattern Detection**: It checks if the FPCR (bits 13-14 of MXCSR) has non-zero values
4. **Event Generation**: When mining patterns are detected, it generates an event with process information

## Event Fields

- `timestamp_raw`: Monotonic timestamp when the event was captured
- `proc`: Process metadata (pid, tid, ppid, uid, gid, comm, etc.)
- `upper_layer`: True if the executable resides on overlayfs upper layer
- `exepath`: Path to the executable file

## Parameters

- `targ_comm`: Filter by process command name
- `targ_gid`: Filter by group ID
- `targ_pid`: Filter by process ID
- `targ_tid`: Filter by thread ID
- `targ_uid`: Filter by user ID

## Usage

```bash
# Build the gadget
make build

# Run the gadget
make run

# Build and run in one command
make build-and-run
```

## Kernel Compatibility

This gadget handles different kernel versions:
- **Kernel ≤ 5.15**: Uses the old FPU structure layout
- **Kernel > 5.15**: Uses the new FPU structure layout

The gadget automatically detects the kernel version and uses the appropriate structure layout for reading FPU registers.
