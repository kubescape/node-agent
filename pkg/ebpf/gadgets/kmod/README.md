# Kernel Module Monitoring Gadget

This gadget monitors kernel module load events by hooking the `init_module` and `finit_module` syscalls.

## Description

The kmod gadget traces kernel module loading operations and reports:
- Process information of the calling process
- Module name being loaded
- Module file path (for finit_module)
- Executable path of the calling process
- Timestamp of the event

## Syscalls Monitored

- `init_module`: Loads a kernel module from memory
- `finit_module`: Loads a kernel module from a file descriptor

## Usage

```bash
# Build the gadget
make build

# Run the gadget
make run

# Build and run in one command
make build-and-run
```

## Output Fields

- `timestamp_raw`: Monotonic timestamp in nanoseconds
- `proc`: Process metadata (pid, tid, ppid, uid, gid, comm, etc.)
- `syscall`: The syscall being monitored ("init_module" or "finit_module")
- `module_name`: Name of the kernel module being loaded
- `module_path`: Path to the module file (for finit_module) or empty (for init_module)
- `exepath`: Executable path of the calling process

## Security Considerations

This gadget can be used to detect:
- Unauthorized kernel module loading
- Rootkit installation attempts
- Suspicious kernel module activity
- Compliance monitoring for kernel module usage

## Requirements

- Linux kernel with eBPF support
- Inspektor Gadget framework
- Appropriate permissions to load eBPF programs
