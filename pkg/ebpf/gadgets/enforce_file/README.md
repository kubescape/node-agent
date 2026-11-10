# enforce_file

Container file access enforcement with BPF LSM. It enforces path rules for six
access kinds: `read`, `write`, `create`, `delete`, `rename` and `chmod`, with
per-access defaults (for example "reads are open, writes go to a workspace
only"), deny exceptions, and a rule kind for files of the container image.

The gadget is built on the [common enforcement library](../common/README.md).
It depends only on Inspektor Gadget and that library. One instance runs per
node, with the same model as enforce_privilege and enforce_network:

- A **slot** is one combination of policy documents; containers with the same
  combination share it. Binding or unbinding a container is a live write to the
  `sbx1_file_bindings` map. The state maps are pinned by name
  (`../common/pin.h`, prefix `sbx1_file_`), so the next load re-opens them. A binding covers its exact cgroup; a subtree binding (a
  parent cgroup bound before its containers start) also covers its descendant
  cgroups. A task that moves into a child cgroup of a Strict exact binding is
  outside its scope: a structural fault, denied (see "Faults").
- The policy maps are frozen per instance. A new or edited policy needs a new
  instance (the owner starts it, binds every container, then stops the old one).
- Only **armed** tasks are judged (`../common/arming.h`): a task is armed when
  it executes a program outside the container runtime's mount namespace, and a
  child inherits the mark. So the runtime's own work in the container cgroup
  (runc init writes `/proc/self/oom_score_adj`, creates `/dev` nodes, and so on)
  is not judged, and an exec into the container or a healthcheck works under a
  write default deny.

`policy/` parses and compiles policy documents; `runtime/` is the native
operator an owner drives with `runtime.WithConfig` and `runtime.GetBindings`.

Requires BPF LSM enabled (`bpf` in `/sys/kernel/security/lsm`),
`CONFIG_SECURITY_PATH` (the `path_*` hooks; every kernel with AppArmor or
Landlock has it), cgroup v2, kernel BTF and Linux 6.2 or later (the
`inode_set_acl` hook). No kfunc is needed: tested on 6.8 and 6.12. Build the image with `make build` (it sets `IG_SOURCE_PATH`, see the
library README).

## Hooks

| Access kind | Hook | Path |
|---|---|---|
| read | `file_open` with `FMODE_READ` | `bpf_d_path(&file->f_path)` |
| write | `file_open` with `FMODE_WRITE` or `O_TRUNC`; `path_truncate` | `bpf_d_path` |
| create | `path_mknod` (open with `O_CREAT`, mknod, mkfifo, AF_UNIX bind), `path_mkdir`, `path_symlink`, `path_link` (new name), `path_rename` (new name that does not exist) | `path_mknod`: dentry walk; others: `bpf_d_path(dir)` + name |
| delete | `path_unlink`, `path_rmdir`, `path_rename` (new name that replaces a file; both names of `RENAME_EXCHANGE`) | `bpf_d_path(dir)` + name |
| rename | `path_rename` (both names), `path_link` (old name) | `bpf_d_path(dir)` + name; link old name: dentry walk |
| chmod | `path_chmod`, `path_chown`, `inode_setxattr` (`security.capability`), `inode_set_acl` (POSIX ACLs) | `bpf_d_path`; inode hooks: dentry walk |

- A read-write open judges both kinds; the most limiting verdict wins. A new
  name that replaces a file by rename is judged as rename, write and delete.
  A new name that does not exist yet (rename, hard link) is judged as create
  and write: the name gets the file's content, so a write-only deny on
  `/etc/ld.so.preload` also stops `mv /tmp/x /etc/ld.so.preload` and an
  `O_TMPFILE` file linked there.
- A file capability (`setcap`) or a POSIX ACL (`setfacl`) changes what a
  file allows without `path_chmod`, so both are judged as `chmod`. The inode
  hooks have a dentry and no mount: a dentry on the file system of the task's
  root mount is walked up to that root (the container path). overlayfs repeats
  the change on its upper file system's inode, and copies a file's attributes
  up the same way, with the credentials of its mounter: that inner call is not
  judged (the overlay call was). A dentry on another file system (a volume)
  is an unresolved path.
- Before Linux 6.11 (upstream commit 61df7b828204), the kernel checks
  `CAP_SYS_ADMIN` for a `security.*` extended attribute only when the
  `inode_setxattr` hooks return 1. Before 6.9 the owner sets the
  `setxattr-allow-one` parameter (`runtime.SetxattrParams`), and
  `inode_setxattr` returns 1 when it allows. From 6.9 it returns 0: IMA and
  EVM are then LSMs that run after BPF LSM, and a return of 1 would stop the
  hook loop before their checks. The verifier of 6.12 rejects a return of 1.
- A deny of another BPF LSM program on the same hook stays a deny: the
  kernel runs the newest program first and no later program after a nonzero
  return (kernel test `TestGadgetEarlierBPFDeny`, 6.8 and 6.12). Each `int`
  hook also returns a negative `ret` (the earlier verdict) before it judges.
- A create is denied at `path_mknod`, before the file exists: a deny at
  `file_open` would leave an empty file. `bpf_d_path` is not allowed in
  `path_mknod`, and the old name of a hard link has no `struct path`; both
  build the path by walking the dentries and mounts up to the task's root, the
  way `d_path` does.
- **Move sources** (the old name of a rename or a hard link, and both names of
  `RENAME_EXCHANGE`) are judged as `rename`, `read` and `write` with the full
  decision (rules, except, fromImage, defaults, merge rule 5); the most
  limiting wins. A second name gives the file's content to whoever can use
  that name, so a file that cannot be read or written under its name cannot
  get another one (`ln /etc/passwd /tmp/p` under a write default deny with
  rename allowed is denied). Both names of `RENAME_EXCHANGE` are also judged
  as `write` and `delete`, like a replaced new name.
- Move sources are also judged against the **guard**: the parent directories
  written in the patterns of deny rules that judge `read` or `write`
  (`/root/.aws/**` guards `/root`; `/home/*/.aws/**` guards `/home/*` and
  `/home`; `/etc/shadow` guards `/etc`; never `/`). So the directory of a
  protected file cannot be renamed away. A rule of other access kinds (a
  `chmod` deny on `/etc/**`, a `delete` deny on every path) neither judges nor
  guards a move: `sed -i` and editors' atomic saves keep working.
- New names (of a rename, a hard link or a symbolic link, and both names of
  `RENAME_EXCHANGE`) are judged against the **new-name guard**: the parent
  directories written in the patterns of deny rules that judge `write` or
  `create`. With `[write, create]` denied on `/root/.aws/config`,
  `mv /tmp/dir /root/.aws` (a directory that brings its own `config`) and
  `ln -s /tmp/dir /root/.aws` are denied; `mkdir /root/.aws` is not (the
  files created in it are judged).
- overlayfs opens the backing file of every overlay file a second time, and
  copy-up opens more files, in the same task. Those opens use a private mount
  (`mnt_ns == MNT_NS_INTERNAL`) and are not judged; a deny there would break
  copy-up.
- `mmap` with `PROT_EXEC` (execMap) is not enforced.

Paths are the paths the container sees (`d_path` resolves against the task's
root). They are the **resolved** paths: a symbolic link in the name a program
opens does not appear. A pattern for `/var/run/x` does not match a file whose
path is `/run/x` (`/var/run` links to `/run` in Debian-based images), and a
file of an orchestrator secret, config map or projected volume is
`dir/..<timestamp>/file`. The owner adds such names (`/dir/..*/file`) to its
patterns; the gadget matches literally. A task whose root is not the root of
its mount (a chroot to a directory) gives paths relative to that directory:
every judged path of that task counts as unresolved. In an enforcing slot the
root barrier denies the chroot itself.

## Policy

```yaml
version: 1
name: ns/name               # qualifies rule names in events
policy:
  mode: enforce             # audit | enforce | off
  file:
    defaults:               # every access kind is required
      read:   {action: allow}
      write:  {action: deny, mode: enforce, origin: example/confined-writes}
      create: {action: deny}
      delete: {action: deny}
      rename: {action: deny}
      chmod:  {action: deny}
    rules:
      - name: workspace
        action: allow
        access: [write, create, delete, rename]   # none listed: all six
        paths: ["/workspace/**", "/tmp/**"]
      - name: no-agent-config
        action: deny
        mode: enforce
        access: [write, create, delete, rename]
        paths: ["**/.claude/**"]
        except: ["/workspace/.claude/settings.local.json"]   # deny rules only
      - {name: no-image-tamper, action: deny, access: [write, delete, rename, chmod], fromImage: true}
```

A rule or default without `mode` takes the policy mode. A rule without `paths`
judges every path and needs `fromImage`. `except` lifts that deny rule for the
listed paths; other rules and the defaults still apply there. See
`examples/policy.yaml`. Limits: 128 rules and 64 KiB per document.

`fromImage: true` limits a rule to overlay files with a lower-layer origin:
the overlay entry of the inode has a lower stack (`ovl_entry.__numlower > 0`).
A copy-up (a write, `chmod`, `touch`, `setxattr`) keeps the origin, so the
file stays an image file; a file created in the container is not one.
`struct ovl_inode` is private to overlayfs: the program reads `oe` one pointer
after the end of the overlay inode's `struct inode`, and `__numlower` at the
start of `struct ovl_entry` (the layout of 6.5 and later; checked on 6.8 and
6.12). The owner reads the layout from the kernel's BTF
(`runtime.FromImageUnavailable`) and sets `FILE_SLOT_FROM_IMAGE` on the slots
only when it holds. Without it no file is an image file: a `fromImage` deny
is not enforced and the owner must report that.

`otherProcess: true` limits a rule to files of the `/proc/<pid>` directory
(and `/proc/<pid>/task/<tid>`) of another process, judged at `file_open`
only. The program reads `pid` of procfs's `struct proc_inode` (in the
kernel's BTF), takes the task that holds it, and compares its `tgid` with the
opening task's. So `/proc/self/environ`, `/proc/<own pid>/environ` and the
process's own threads do not match, whatever the PID namespace. A pid whose
process exited counts as another process. The check reads the inode, so
`paths: ["/**/environ"]` with `otherProcess` stops a process from reading
another process's environment under any proc mount point (tested on 6.8 and
6.17). The check runs after the binding lookup, so unbound tasks do not pay
for it. Such a rule needs no guard, and its rank applies to an unresolved
path only when the file belongs to another process (`unresolved_other`).

## Patterns

A pattern is an absolute path glob, or one that starts with `**`. Segments are
separated by `/`:

| Segment | Matches |
|---|---|
| `name` | one component, exactly |
| `*` | one whole component |
| `**` | zero or more components (`/a/**` also matches `/a`) |
| `pre*suf` | one component that starts with `pre` and ends with `suf` (each at most 16 bytes): `cron*`, `*.sock`, `rc*.d` |

`**x` is the same as `**/*x` (`/run/containerd/**.sock`); consecutive `**`
collapse. Rejected: `?`, `[...]`, more than one `*` in a segment, empty, `.`
and `..` segments, relative paths.

## How it decides

For each judged access, per slot:

1. Match the path once: a shift-and automaton over path components. Each
   pattern owns one bit per segment; one hash lookup per component
   (`file_literals`), plus the slot's glob table and the `*`/`**` masks. The
   result is the set of patterns that match.
2. Rank every rule of the access kind whose paths match (and whose except
   paths do not, and whose `fromImage` holds): deny enforce > deny audit >
   allow. No rule matches: the access kind's default.
3. Several documents in a slot merge per access kind by the shared contract
   (`../common/merge/CONTRACT.md`): the merged default of an access kind is
   deny if any document's default is deny; when every matching rule denies,
   the enforce default deny of each document without a matching rule still
   applies. `policy/contract_test.go` runs the shared vectors (key = path,
   qualifier = access kind).
4. A path that cannot be resolved (a `d_path` error, longer than 4096 bytes,
   deeper than 64 components in the walk) takes the most limiting rule or
   default of the access kind (rule `unresolved-path`): fail closed.

Only `deny` with mode `enforce` returns `-EPERM`; a deny in audit mode is
reported and allowed.

## Faults

- **Structural.** A bound cgroup whose slot has no policy (generation 0), a
  task outside a Strict exact binding's scope, or a missing scratch buffer. A
  Strict binding denies the armed task (`-EPERM`) and counts a slot fault in
  `arming_faults`; an Audit binding allows. Both count in `counters` slot 4 and
  send a file verdict with hook `fault`, rule `fault`, reason
  `operational_error` and `access` `structural`.
- **Tracking.** A lost arming mark. In a Strict binding a fork is refused and
  a lost exec mark is counted; both count a slot fault and send a `fault`
  verdict with `access` `tracking`. Audit never blocks: outside a Strict
  binding the fork is allowed, and a `CLONE_INTO_CGROUP` fork counts a node
  fault (`arming_witness`), which the owner reports against every Strict
  binding.
- **Runtime helpers.** Only a binding with `BINDING_RUNTIME_HELPERS` (the
  owner sets it on a parent cgroup bound before its containers start) leaves
  OCI hooks unarmed; container bindings have no helper exemption. Exempted
  execs are counted (`arming_witness`).

A nonzero slot fault count makes the binding's protection unconfirmed in the
policy status.

## Root barrier

The path a rule names is only meaningful while the task keeps its root and
its mount tree. The gadget includes the shared root barrier
(`../common/root_barrier.h`): every armed task of a **Strict** binding (its
slot has at least one enforce deny, `file_slot.mode` 2), in the bound cgroup or
outside its exact scope, cannot `chroot`, `pivot_root`, create a user
namespace, create or join a mount namespace, or change the mount tree. Those
calls fail with `-EPERM`, are counted in `root_barrier_counters`, and each
sends a file verdict: hook `root_barrier`, rule `root-barrier`, reason
`root_barrier`, the operation in `access`. A Strict file section denies these
operations whatever the privilege section says, so a privilege rule that only
audits a mount does not make that mount pass in such a container; the file
verdict shows why. Thread creation and `setns` into other namespace types
stay allowed. A bound slot with no policy is a barrier fault: denied under
Strict, allowed under Audit, both counted in `root_barrier_faults`.

`ig_file_alloc` carries the barrier's `task_alloc` body first
(`ROOT_BARRIER_NO_TASK_ALLOC_PROGRAM`), so the barrier denies a clone before the
arming mark is allocated; the attestation names that program
(`runtime.BarrierHooks`).

Tasks of an audit slot are never covered: audit stays non-blocking. Unarmed
tasks (the container runtime's own setup) are not covered either.

The owner attests the barrier at Ready (`rootbarrier.Verify`: BPF LSM active,
every hook signature as expected, a live LSM link per program, and a self-test
that real calls are denied). When the attestation fails, Ready refuses the
instance if an initial binding is on an enforcing slot; otherwise the instance
starts, `GetBarrier(gc).Err()` reports the failure, and the node owner refuses
bindings to enforcing slots and reports them as not healthy. Audit-only
bindings never depend on the barrier.

Component hashes are FNV-1a 64 with the offset basis replaced by a random seed
per slot, picked by the compiler (with no collision between the slot's
literals). The Go simulator in `policy/` runs the same step function, and
`policy/harness_test.go` compiles `file_policy.h` natively and checks that the
C matcher and decision give the same results.

## Limits

Per node: 1024 containers, 64 slots, 16384 literal components. Per slot: 32
documents, 64 rules, 256 pattern segments, 16 distinct glob segments. The
compiler refuses a combination over a limit. Patterns that repeat (in several
rules or documents) use their segments once; the guard of a pattern needs no
segments of its own.

Cost per `open` (median of 5 x 1M open+close of a 5-level path, one 51-rule
policy, shared lab VMs, so about ±100 ns): the program loaded, container not
bound: +185 ns (6.12) / +305 ns (6.8, the first program on `file_open` there);
bound: +280 ns (6.12) / +305 ns (6.8) more.

An unbound task pays one hash lookup per cgroup level (its own cgroup and
each parent, for the child-cgroup coverage). `file_open` skips overlayfs'
backing open before that lookup, so an overlay open walks once, not twice.
Program time per unbound open (`kernel.bpf_stats_enabled`, which adds its
own overhead): about 75 ns at cgroup level 2 (Docker) and 100 ns at level 4
(a container under three parent slices, as an orchestrator places it), on
6.8 and 6.12; a lookup of the own cgroup only would be about 70 ns.

## Known limits

- Hard links and bind mounts that exist before the policy binds keep a second
  name for a file; a path rule sees only the name used.
- The guard covers the parents written in a pattern, not the parents of a
  floating `**/` part: renaming a directory that contains `.claude/` is not
  guarded by `**/.claude/**`; a parent between `**` and the next literal is not
  guarded either.
- `/proc/<pid>/root/...` of another container gives the same path string; the
  opener's policy judges that path.
- An audit slot is not covered by the root barrier (see "Root barrier"), so
  its tasks can still change their path view. A chroot to a directory makes
  every path of such a task unresolved; a chroot to the root of a mount (for
  example a volume) is not detected, and a bind mount made after binding
  gives a file a second name. Audit verdicts of such a task can therefore miss
  an access. In an enforcing slot the barrier stops such changes after
  binding; a chroot, mount or mount namespace that already exists when the
  container is bound (or that was made while it was in an audit slot) stays.
- The dentry walk (`path_mknod`, hard link old name, inode hooks) does not take
  the kernel's rename and mount sequence locks: a concurrent rename can give a
  torn path.
- A file capability or a POSIX ACL on a volume file is an unresolved path:
  under a policy with a `chmod` deny rule, `setcap`, `setfacl` and copies that
  keep them (`cp -a`, `tar --xattrs`) fail there. A task that sets an
  attribute on a volume file through io_uring with registered credentials
  (`IORING_REGISTER_PERSONALITY`) looks like overlayfs' inner call and is not
  judged. Removing an ACL (`inode_remove_acl`) is not judged.
- Kernel issue, not caused or closed by this gadget: on a kernel before Linux
  6.11 (upstream 61df7b828204) with BPF LSM active, the BPF LSM default of
  `inode_setxattr` and `inode_removexattr` is 0, so the kernel skips its
  `CAP_SYS_ADMIN` check of `security.*` attributes for every task (verified on Ubuntu 6.8: a user
  without capabilities sets `security.test` with no BPF program loaded). Before
  6.9, where the verifier accepts a return of 1, the gadget returns 1 from
  `inode_setxattr` and so restores the `setxattr` check while it runs. Kernels
  with the LSM return value check backported (Ubuntu 6.8) reject a return of
  1: there the gadget returns 0 and the kernel issue stays. `inode_removexattr`
  is not attached.
- On images where `/bin`, `/sbin`, `/lib` and `/lib64` are not links into
  `/usr` (for example Alpine), a deny rule on `/lib/**` also covers
  `/usr/lib/**`: the owner's policy translator adds the merged `/usr` forms to
  every deny rule and its excepts, because it does not know the image layout.
- A Secret or ConfigMap key with a directory (`items: path: a/b/file`) is
  resolved under a `..<timestamp>` directory higher up
  (`/dir/..<timestamp>/a/b/file`). The owner's policy translator adds the
  `..<timestamp>` form only before the last path segment, so a rule on
  `/dir/a/b/file` does not match that file.
- A `mknod` or `mkdir` new name is not judged against the new-name guard, and
  a symbolic link's new name is not judged as `write`: a symbolic link at a
  write-only denied name that does not exist yet gives that name other
  content.
- `fromImage` needs the overlay layout of Linux 6.5 and later (see
  "Policy"); on another layout it is off.
- A file that replaces an image file by rename (a new inode) is not an image
  file.
- A file opened through `/proc/self/fd/N` after it was deleted is judged with
  the path `d_path` gives (`... (deleted)`).
- Matching hashes path components. The seed is random per slot, but FNV-1a is
  not a keyed cryptographic hash.
- The path buffer is per CPU. If a hook is preempted and another task uses the
  buffer on the same CPU, the hook detects it and judges the path again; a
  second clash counts as an unresolved path (fail closed).
- execMap (`mmap`/`mprotect` with `PROT_EXEC`), file system type and actor
  conditions are not enforced.

## Maps and events

| Map | Content |
|---|---|
| `sbx1_file_file_slots` | pinned array, storage index → generation, hash seed, mode, flags (`FILE_SLOT_FROM_IMAGE`), segment masks (`first`, `star`, `wild`, `accept`, `init`), merged default and enforce-deny documents per access kind, unresolved ranks, glob table, up to 64 rules `{match, except, guard bits, access mask, rank, document, flags, rule_id, origin_id}` |
| `sbx1_file_file_literals` | pinned hash, `{storage index, component hash}` → the segment bits the component matches |
| `sbx1_file_bindings`, `sbx1_file_slot_state`, `sbx1_file_armed_tasks`, `sbx1_file_arming_faults` (pinned), `counters` | from the common library |

The `verdict` datasource shares `generation`, `cgroup`, `deny` and `mode` with
the other enforcement gadgets and adds `host_pid`, `rule_id`, `origin_id`,
`is_default`, `slot`, `comm`, `hook` (the program that judged), `access` (the
access kind that decided; `FILE_ACCESS_MOVE_SOURCE` and
`FILE_ACCESS_NEW_NAME` for the guards),
`from_image` and `path` (the path that decided, cut at 511 bytes; empty when
unresolved). Only denies are reported (mode 1 = audit, the access was
allowed). Rule and origin names are in the owner's compiled policy
(`RuleNames`: 1 is `default`, 2 is `unresolved-path`; `Origins`). Origin id 0
means no origin; an explicit empty origin has its own id. A default verdict
(rule `default`) carries the origin of one deciding document; all the default
origins of the documents that agree with the merged default of an access kind
are in `DefaultOrigins[slot][access]`. Reporting is
limited to 100 events per CPU per second; enforcement is never throttled.
