# Workflow token permission validation

## Target branch

PR #1011 intentionally targets `main`. On 2026-10-16 the upstream repository's
default branch was `main`, and `git ls-remote` returned no `refs/heads/dev`.
The release entrypoint also filters merged PRs to `main`. The PR template's
request to target `dev` cannot be followed while that branch does not exist.
This records the contributor's target choice; it does not claim maintainer approval.

## Permission paths

GitHub permits reusable workflows to maintain or reduce their caller's token
permissions, including through nested calls. See the
[reusable workflow reference](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations#access-and-permissions-for-nested-workflows).
The four reusable workflows use `contents: read` defaults so they fit within
their callers' explicit ceilings. Each job still declares its own required
permissions. A broad `read-all` reusable default requests unrelated read scopes
which the calling jobs do not grant.

| Path / job | Required token permissions | Purpose |
| --- | --- | --- |
| `pr-created` -> `incluster-comp-pr-created/test` -> `go-basic-tests/Environment-Test` | `contents: read`, `actions: read`, `security-events: write` at each calling/leaf job | Checkout, CodeQL workflow metadata and result upload |
| `pr-merged/pr-merged` and `bypass/pr-merged` -> `incluster-comp-pr-merged` | `contents: write`, `id-token: write`, `attestations: write`, `artifact-metadata: write`, `pull-requests: write` | Ceiling for all release jobs, including the nested benchmark |
| `incluster-comp-pr-merged/docker-build` | `contents: read`, `id-token: write`, `attestations: write`, `artifact-metadata: write` | Checkout, signing, attestation and storage records |
| `incluster-comp-pr-merged/create-release-and-retag` | `contents: write` | Create the GitHub release |
| `incluster-comp-pr-merged/benchmark` -> `benchmark/benchmark` | `contents: read`, `pull-requests: write` | Checkout and benchmark PR comment |
| `go-basic-tests/Check-secret`, `incluster-comp-pr-merged/run-tests` | `{}` | Secret-presence check; private E2E uses a separate GitHub App token |

The [pinned attestation action's documentation](https://github.com/actions/attest/blob/59d89421af93a897026c735860bf21b6eb4f7b26/README.md#usage)
documents the three write scopes used by the image attestation job.
`artifact-metadata: write` is for storage records; its previous absence does
not by itself establish an attestation failure. Quay publishing uses registry
credentials, and Helm dispatch uses a separate personal access token.

## Repeatable local checks

Install PyYAML in your Python environment if needed, then run from the repo root:

```sh
python3 scripts/check-workflow-permissions.py
actionlint -shellcheck= -pyflakes= -oneline
bash scripts/check-inspektor-gadget-pin.sh
git diff --check
```

The permission check validates all workflow defaults, every local reusable call
including nested paths, both callee defaults and effective job permissions,
and 11 operation-specific permission maps. It does not skip permission checks
based on job conditions. It accepts an optional repository root for checking
an extracted revision without changing the checkout.

Validation on 2026-10-16:

- All 10 read-only workflow defaults, five local call edges and 11 operation
  maps passed. The release chain is checked from both entrypoints.
- In temporary copies, the check rejected all four reusable defaults restored
  to `read-all`, and all 19 individual removals of required write permissions
  (23 negative cases in total).
- Actionlint v1.7.12 reported the same eight diagnostic identities as PR base
  `67e455e040520a3f1f5a4ac20fbf5fe25f676d43`, ignoring moved line numbers.
  These concern the custom `ubuntu-large` runner label (two), unsupported
  `comment-tag` input, undeclared reusable-workflow secret, and obsolete
  action runtimes (four). There were no new diagnostics.
- YAML comparison against `8863e2312d97c3bf3f6d90c9a92597deedf4e3c7` confirmed
  the follow-up changes only reusable workflow defaults, with job/step behavior
  unchanged. `git diff --check` passed.
- The pin script's local temporary-pin marker check passed. Its best-effort
  GitHub ancestry lookup was inconclusive because the API request failed.
- Scorecard was not rerun: downloading the v5.5.0 binary failed because GitHub
  was unreachable. The earlier PR's 10/10 result is historical evidence only.

## Hosted evidence and remaining gate

The [component suite](https://github.com/kubescape/node-agent/actions/runs/37035183803)
and [Inspektor Gadget pin check](https://github.com/kubescape/node-agent/actions/runs/37035183838)
both succeeded for the earlier head
`8863e2312d97c3bf3f6d90c9a92597deedf4e3c7`. Those runs do not cover this
follow-up or prove the release/CodeQL chains. The original workflow-only diff
was excluded by those chains' PR path filters. Adding the Python permission
checker makes this follow-up eligible for the PR-created chain; its result must
be inspected after pushing. The merged-release path still needs a qualifying
upstream event.

The checks above are static evidence. They do not validate GitHub's issued
tokens, fork permission downgrades, registry credentials, OIDC, release creation,
SARIF upload, private E2E dispatch, or benchmark execution. The existing CodeQL
v2 runtime diagnostics are also outside this permission change. Application Go
and cluster tests were not run locally for this workflow-only change.

Maintainer acceptance of this static gate, or an upstream run exercising the
release and CodeQL operations, remains required before claiming runtime
validation. The nonblocking observation about unused PR-write authority on
release benchmarks remains: the comment step runs only on `pull_request`, but
the reusable job's declared write scope still needs a compatible caller ceiling.
