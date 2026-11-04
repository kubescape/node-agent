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
  `bindings` map. A task that moves into a child cgroup of a bound cgroup stays
  covered (up to 32 levels).
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
Landlock has it), cgroup v2 and kernel BTF. No kfunc is needed: tested on 6.8
and 6.12. Build the image with `make build` (it sets `IG_SOURCE_PATH`, see the
library README).

## Hooks

| Access kind | Hook | Path |
|---|---|---|
| read | `file_open` with `FMODE_READ` | `bpf_d_path(&file->f_path)` |
| write | `file_open` with `FMODE_WRITE` or `O_TRUNC`; `path_truncate` | `bpf_d_path` |
| create | `path_mknod` (open with `O_CREAT`, mknod, mkfifo, AF_UNIX bind), `path_mkdir`, `path_symlink`, `path_link` (new name), `path_rename` (new name that does not exist) | `path_mknod`: dentry walk; others: `bpf_d_path(dir)` + name |
| delete | `path_unlink`, `path_rmdir`, `path_rename` (new name that replaces a file) | `bpf_d_path(dir)` + name |
| rename | `path_rename` (both names), `path_link` (old name) | `bpf_d_path(dir)` + name; link old name: dentry walk |
| chmod | `path_chmod`, `path_chown` | `bpf_d_path` |

- A read-write open judges both kinds; the most limiting verdict wins. A new
  name that replaces a file by rename is judged as rename, write and delete.
- A create is denied at `path_mknod`, before the file exists: a deny at
  `file_open` would leave an empty file. `bpf_d_path` is not allowed in
  `path_mknod`, and the old name of a hard link has no `struct path`; both
  build the path by walking the dentries and mounts up to the task's root, the
  way `d_path` does.
- **Move sources** (the old name of a rename or a hard link, and both names of
  `RENAME_EXCHANGE`) are also judged against the **guard** of every deny rule
  of any access kind: its paths and the parent directories in them
  (`/root/.aws/**` guards `/root/.aws` and `/root`; `/home/*/.aws/**` guards
  `/home/*/.aws`, `/home/*` and `/home`; never `/`). So a protected file cannot
  get a second, unprotected name by a hard link or a rename, and its directory
  cannot be renamed away.
- overlayfs opens the backing file of every overlay file a second time, and
  copy-up opens more files, in the same task. Those opens use a private mount
  (`mnt_ns == MNT_NS_INTERNAL`) and are not judged; a deny there would break
  copy-up.
- `mmap` with `PROT_EXEC` (execMap) is not enforced.

Paths are the paths the container sees (`d_path` resolves against the task's
root).

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

`fromImage: true` limits a rule to files of the image's lower overlay layer
that this container has not modified: the inode is an overlay inode whose
upper dentry is not set. A lower file opened for write is still lower at
`file_open` (copy-up runs after the hook).

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

## Known limits

- Hard links and bind mounts that exist before the policy binds keep a second
  name for a file; a path rule sees only the name used.
- The guard covers the parents written in a pattern, not the parents of a
  floating `**/` part: renaming a directory that contains `.claude/` is not
  guarded by `**/.claude/**`; a parent between `**` and the next literal is not
  guarded either.
- `/proc/<pid>/root/...` of another container gives the same path string; the
  opener's policy judges that path.
- A chroot in the container changes the path the hooks see. Deny chroot with
  the privilege gadget, or treat it as a known gap.
- The dentry walk (`path_mknod`, hard link old name) does not take the kernel's
  rename and mount sequence locks: a concurrent rename can give a torn path.
- `fromImage` is false after the first copy-up of the file in this container.
  A chmod copies the file up (and so does a write that is allowed), so a rule
  that protects image files from writes should also deny `chmod`. With
  overlay `metacopy=on`, a chmod-only copy-up also makes the file "upper".
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
| `file_slots` | array, slot → generation, hash seed, mode, segment masks (`first`, `star`, `wild`, `accept`, `init`), merged default and enforce-deny documents per access kind, unresolved ranks, glob table, up to 64 rules `{match, except, guard bits, access mask, rank, document, flags, rule_id, origin_id}` |
| `file_literals` | hash, `{slot, component hash}` → the segment bits the component matches |
| `bindings`, `counters`, `armed_tasks`, `arming_faults` | from the common library |

The `verdict` datasource shares `generation`, `cgroup`, `deny` and `mode` with
the other enforcement gadgets and adds `host_pid`, `rule_id`, `origin_id`,
`is_default`, `slot`, `comm`, `hook` (the program that judged), `access` (the
access kind that decided; `FILE_ACCESS_MOVE_SOURCE` for the guard),
`from_image` and `path` (the path that decided, cut at 511 bytes; empty when
unresolved). Only denies are reported (mode 1 = audit, the access was
allowed). Rule and origin names are in the owner's compiled policy
(`RuleNames`: 1 is `default`, 2 is `unresolved-path`; `Origins`). Reporting is
limited to 100 events per CPU per second; enforcement is never throttled.
