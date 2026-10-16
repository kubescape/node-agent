# trace_exec TTY backport

This gadget is vendored from [Inspektor Gadget v0.48.1](https://github.com/inspektor-gadget/inspektor-gadget/tree/v0.48.1/gadgets/trace_exec)
with only the terminal device-number change from upstream commit
[`c6fc831a`](https://github.com/inspektor-gadget/inspektor-gadget/commit/c6fc831a)
backported to the BPF program and field metadata.

`tty_major` and `tty_minor` distinguish `/dev/pts/0` from a process without a
controlling terminal. The v0.48.1 argument collection is retained: `args[0]`
is the execve pathname, which existing container profiles and executable-path
consumers depend on. Later upstream argument-parsing changes are not included.

The local build uses `ghcr.io/inspektor-gadget/gadget/trace_exec:v0.48.1-tty`;
this is a custom artifact, not an upstream release. The Go postprocessor pins
v0.48.1 instead of using the upstream monorepo's relative module replacement.
Upstream source license headers are preserved.

Validate with `make gadgets`, `TestExecFields`, and the component tests
`Test_32_UnexpectedProcessArguments` and `Test_35_ExecTTYFieldTest` against an
image containing the rebuilt `tracers.tar`.
