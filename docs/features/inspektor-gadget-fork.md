# inspektor-gadget fork

node-agent depends on a fork of `inspektor-gadget/inspektor-gadget` via a `replace`
directive in `go.mod`, instead of the upstream module, because node-agent needs
changes (e.g. eBPF map manual-fetch triggers, syscall map handling) before they land
upstream.

## Current fork

The fork is **`github.com/kubescape/inspektor-gadget`**, pinned to a specific commit
via a pseudo-version:

```
replace github.com/inspektor-gadget/inspektor-gadget => github.com/kubescape/inspektor-gadget v0.0.0-<timestamp>-<short-sha>
```

This is an org-owned fork of `inspektor-gadget/inspektor-gadget`, kept as a plain
mirror of whatever commit node-agent currently needs — it is not meant to diverge
with its own history. Previously this pointed at a personal fork
(`matthyx/inspektor-gadget`); that was migrated to the org fork so the dependency
isn't tied to one contributor's personal account.

## Updating the pin

1. Push (or force-push) the desired commit to `kubescape/inspektor-gadget:main`.
2. Update the `replace` line in `go.mod` with the new commit's pseudo-version:
   ```
   go get github.com/inspektor-gadget/inspektor-gadget@<commit-sha>
   ```
3. Run `go mod tidy` and `go build ./...` to confirm `go.sum` and the build are consistent.

The pin is a point-in-time snapshot, not a tracking reference — moving
`kubescape/inspektor-gadget:main` further does not update `go.mod` automatically.
