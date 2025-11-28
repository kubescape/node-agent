# BPF Gadget

This gadget monitors the `bpf` syscall to track eBPF program operations and system calls.

## Description

The bpf gadget traces calls to the `bpf` system call, which is used for various eBPF operations including loading programs, creating maps, attaching programs to hooks, and more. This is essential for monitoring eBPF-based security tools, networking applications, and observability tools.

## Syscall Signature

```c
int bpf(int cmd, union bpf_attr *attr, unsigned int size);
```

## What it monitors

- **bpf syscall**: Monitors when processes call the `bpf` system call
- **Command**: Captures the BPF command being executed (first parameter)
- **Attribute size**: Shows the size of the union bpf_attr structure (third parameter)
- **Process information**: Includes process metadata (PID, UID, GID, command, etc.)
- **Executable path**: Shows the path of the executable making the bpf call
- **Upper layer detection**: Identifies if the process is running in an overlay filesystem upper layer

## Common BPF commands

- `BPF_MAP_CREATE` (0): Create a new eBPF map
- `BPF_MAP_LOOKUP_ELEM` (1): Look up an element in an eBPF map
- `BPF_MAP_UPDATE_ELEM` (2): Update an element in an eBPF map
- `BPF_MAP_DELETE_ELEM` (3): Delete an element from an eBPF map
- `BPF_MAP_GET_NEXT_KEY` (4): Get the next key in an eBPF map
- `BPF_PROG_LOAD` (5): Load an eBPF program
- `BPF_OBJ_PIN` (6): Pin an eBPF object to the filesystem
- `BPF_OBJ_GET` (7): Get an eBPF object from the filesystem
- `BPF_PROG_ATTACH` (8): Attach an eBPF program to a hook
- `BPF_PROG_DETACH` (9): Detach an eBPF program from a hook
- `BPF_PROG_TEST_RUN` (10): Test run an eBPF program
- `BPF_PROG_GET_NEXT_ID` (11): Get the next program ID
- `BPF_MAP_GET_NEXT_ID` (12): Get the next map ID
- `BPF_PROG_GET_FD_BY_ID` (13): Get file descriptor by program ID
- `BPF_MAP_GET_FD_BY_ID` (14): Get file descriptor by map ID
- `BPF_OBJ_GET_INFO_BY_FD` (15): Get object info by file descriptor
- `BPF_PROG_QUERY` (16): Query program information
- `BPF_RAW_TRACEPOINT_OPEN` (17): Open raw tracepoint
- `BPF_BTF_LOAD` (18): Load BTF (BPF Type Format)
- `BPF_BTF_GET_FD_BY_ID` (19): Get BTF file descriptor by ID
- `BPF_TASK_FD_QUERY` (20): Query task file descriptor
- `BPF_MAP_LOOKUP_AND_DELETE_ELEM` (21): Look up and delete element
- `BPF_MAP_FREEZE` (22): Freeze a map
- `BPF_BTF_GET_NEXT_ID` (23): Get next BTF ID
- `BPF_MAP_LOOKUP_BATCH` (24): Batch lookup in map
- `BPF_MAP_LOOKUP_AND_DELETE_BATCH` (25): Batch lookup and delete
- `BPF_MAP_UPDATE_BATCH` (26): Batch update in map
- `BPF_MAP_DELETE_BATCH` (27): Batch delete from map
- `BPF_LINK_CREATE` (28): Create a link
- `BPF_LINK_UPDATE` (29): Update a link
- `BPF_LINK_GET_FD_BY_ID` (30): Get link file descriptor by ID
- `BPF_LINK_GET_NEXT_ID` (31): Get next link ID
- `BPF_ENABLE_STATS` (32): Enable statistics
- `BPF_ITER_CREATE` (33): Create an iterator
- `BPF_LINK_DETACH` (34): Detach a link
- `BPF_PROG_BIND_MAP` (35): Bind a program to a map

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
- BPF command
- Attribute size
- Timestamp
- Upper layer status

## Security implications

Monitoring BPF syscalls is crucial for security because:
- eBPF programs can be used for malicious purposes
- BPF programs can bypass traditional security controls
- Unauthorized BPF program loading could indicate compromise
- BPF maps can be used for data exfiltration or persistence
