# Unshare Gadget

This gadget monitors the `unshare` syscall to track namespace unsharing operations.

## Description

The unshare gadget traces calls to the `unshare` system call, which allows a process to disassociate parts of its execution context that are currently being shared with other processes. This is commonly used for containerization and namespace isolation.

## What it monitors

- **unshare syscall**: Monitors when processes call the `unshare` system call
- **Flags**: Captures the flags parameter that indicates which namespaces to unshare
- **Process information**: Includes process metadata (PID, UID, GID, command, etc.)
- **Executable path**: Shows the path of the executable making the unshare call
- **Upper layer detection**: Identifies if the process is running in an overlay filesystem upper layer

## Common unshare flags

- `CLONE_NEWNS` (0x00020000): Unshare mount namespace
- `CLONE_NEWUTS` (0x04000000): Unshare UTS namespace  
- `CLONE_NEWIPC` (0x08000000): Unshare IPC namespace
- `CLONE_NEWPID` (0x20000000): Unshare PID namespace
- `CLONE_NEWNET` (0x40000000): Unshare network namespace
- `CLONE_NEWUSER` (0x10000000): Unshare user namespace
- `CLONE_NEWCGROUP` (0x02000000): Unshare cgroup namespace

## Usage

```bash
# Build the gadget
make build

# Run the gadget
make run

# Build and run in one command
make build-and-run
```

## Output

The gadget outputs JSON events containing:
- Process information (PID, UID, GID, command)
- Executable path
- Unshare flags
- Timestamp
- Upper layer status
