#!/usr/bin/env bash
#
# check-inspektor-gadget-pin.sh
#
# Guards against a go.mod `replace` directive for
# github.com/inspektor-gadget/inspektor-gadget being left pinned at a
# temporary/unmerged commit on the kubescape/inspektor-gadget fork.
#
# This check is ported from armosec/private-node-agent's
# scripts/check-inspektor-gadget-pin.sh, which was added after that repo hit
# this exact failure mode once in its own history: a replace pin was
# repointed at a commit on a short-lived branch for a "stack immediately"
# workflow, and the re-pin to the real merged SHA was forgotten before the
# consuming PR merged (see that repo's commit d358344, the follow-up fix to
# its PR #540). This repo vendors the same fork via the same replace pattern
# (see go.mod), so it is exposed to the same mistake and gets the same guard.
#
# This is intentionally a MECHANICAL check, not a human-readable `NOTE:`
# comment relying on someone noticing it during review (that's exactly the
# thing that failed before).
#
# Two independent signals are checked, in order of priority:
#
#   1. A `NOTE:`-style comment immediately above the replace line that
#      mentions "re-pin" / "repin" / "merged SHA" is treated as an explicit,
#      self-declared "this is a temporary pin, do not merge yet" marker.
#      Its mere presence is an automatic hard failure. This is the PRIMARY
#      check: it is deterministic, requires no network access, and cannot be
#      defeated by network flakiness or the target repo being private/
#      rate-limited. It relies on the convention that whoever does a
#      temporary "stack immediately" repoint of this replace line adds such
#      a comment.
#
#   2. A best-effort ancestor check against kubescape/inspektor-gadget:main
#      via the public GitHub REST "compare" API (no auth needed for a public
#      repo read). This is DEFENSE IN DEPTH for the case where the NOTE
#      comment is stripped without the pin actually having been updated to a
#      merged commit. It is deliberately best-effort: if the network call
#      fails, times out, or the repo/commit can't be reached (e.g. CI
#      runner has no egress, GitHub API rate limit, repo visibility changes),
#      this script WARNS but does not fail the build on that alone -- a
#      flaky network check would make this gate itself unreliable, which is
#      worse than not having signal #2 at all. It only hard-fails when the
#      API gives a definitive, unambiguous answer that the pinned commit is
#      NOT an ancestor of main (compare status "ahead" or "diverged").
#
#      Note: `git ls-remote` alone cannot answer an ancestor question (it
#      only maps refs to their tip SHA, not arbitrary-commit ancestry), so
#      the GitHub compare API is used instead -- it answers the actual
#      question directly without needing a full/shallow clone of the fork.
#
# Usage:
#   scripts/check-inspektor-gadget-pin.sh [path/to/go.mod]
#
# Exit codes:
#   0 - OK (no replace directive found, or it passed both checks)
#   1 - FAIL (NOTE marker present, or commit confirmed not merged to main)
#
set -euo pipefail

GOMOD="${1:-go.mod}"
TARGET_MODULE="github.com/inspektor-gadget/inspektor-gadget"
GUARDED_FORK="github.com/kubescape/inspektor-gadget"
GUARDED_FORK_API="https://api.github.com/repos/kubescape/inspektor-gadget"

if [[ ! -f "$GOMOD" ]]; then
    echo "check-inspektor-gadget-pin: ${GOMOD} not found" >&2
    exit 1
fi

# Find the line number of the replace directive for the guarded module.
replace_line_no=$(grep -nE "^replace[[:space:]]+${TARGET_MODULE//./\\.}[[:space:]]*=>" "$GOMOD" | head -1 | cut -d: -f1 || true)

if [[ -z "$replace_line_no" ]]; then
    echo "check-inspektor-gadget-pin: no 'replace ${TARGET_MODULE} => ...' directive in ${GOMOD}; nothing to check."
    exit 0
fi

replace_line=$(sed -n "${replace_line_no}p" "$GOMOD")
echo "check-inspektor-gadget-pin: found replace directive at ${GOMOD}:${replace_line_no}:"
echo "  ${replace_line}"

# --- Signal 1: NOTE-style "must be re-pinned" comment immediately above ---
#
# Walk upward from the replace line collecting the contiguous block of `//`
# comment lines directly preceding it (stopping at the first blank/non-
# comment line), then look for a NOTE marker inside that block.
comment_block=""
line_no=$((replace_line_no - 1))
while [[ $line_no -ge 1 ]]; do
    line=$(sed -n "${line_no}p" "$GOMOD")
    if [[ "$line" =~ ^[[:space:]]*// ]]; then
        comment_block="${line}"$'\n'"${comment_block}"
        line_no=$((line_no - 1))
    else
        break
    fi
done

if echo "$comment_block" | grep -qiE 'NOTE'; then
    if echo "$comment_block" | grep -qiE 're-?pin|merged[[:space:]]+SHA'; then
        echo "" >&2
        echo "check-inspektor-gadget-pin: FAIL" >&2
        echo "" >&2
        echo "A NOTE comment above the ${TARGET_MODULE} replace directive marks" >&2
        echo "this pin as temporary and pending re-pin to a merged SHA:" >&2
        echo "" >&2
        echo "$comment_block" | sed 's/^/  /' >&2
        echo "" >&2
        echo "This PR must not merge with that marker still in place. Re-pin the" >&2
        echo "replace directive to the merged commit SHA on the target fork's" >&2
        echo "main branch, then remove the NOTE comment." >&2
        exit 1
    fi
fi

# --- Signal 2: best-effort ancestor check against kubescape/inspektor-gadget:main ---
#
# Only meaningful when the replace target is the guarded fork; other forks
# (e.g. a developer's personal fork used for short-lived iteration) are not
# in scope for this specific safeguard.
replace_module=$(echo "$replace_line" | sed -E 's/^replace[[:space:]]+[^[:space:]]+[[:space:]]*=>[[:space:]]*([^[:space:]]+).*/\1/')
replace_version=$(echo "$replace_line" | sed -E 's/^replace[[:space:]]+[^[:space:]]+[[:space:]]*=>[[:space:]]*[^[:space:]]+[[:space:]]+([^[:space:]]+).*/\1/')

if [[ "$replace_module" != "$GUARDED_FORK" ]]; then
    echo "check-inspektor-gadget-pin: replace target is '${replace_module}', not '${GUARDED_FORK}'; skipping ancestor check (only in scope for the guarded fork)."
    echo "check-inspektor-gadget-pin: PASS (no NOTE marker found)"
    exit 0
fi

# Go pseudo-versions end in -<12 hex chars> (the abbreviated commit hash).
pinned_commit=$(echo "$replace_version" | grep -oE '[0-9a-f]{12}$' || true)

if [[ -z "$pinned_commit" ]]; then
    echo "check-inspektor-gadget-pin: version '${replace_version}' is not a pseudo-version (no trailing 12-hex commit); assuming it's a tagged release and skipping ancestor check."
    echo "check-inspektor-gadget-pin: PASS (no NOTE marker found)"
    exit 0
fi

echo "check-inspektor-gadget-pin: checking whether ${pinned_commit} is an ancestor of ${GUARDED_FORK}:main ..."

compare_json=$(curl -sS --max-time 10 \
    -H "Accept: application/vnd.github+json" \
    "${GUARDED_FORK_API}/compare/main...${pinned_commit}" 2>/dev/null) || compare_json=""

if [[ -z "$compare_json" ]]; then
    echo "check-inspektor-gadget-pin: WARNING - could not reach GitHub API to verify ancestry (network issue, rate limit, or private repo without auth). Not failing the build on this alone; relying on signal 1 (NOTE marker check, which passed)."
    echo "check-inspektor-gadget-pin: PASS (best-effort ancestor check inconclusive, no NOTE marker found)"
    exit 0
fi

status=$(echo "$compare_json" | grep -oE '"status"[[:space:]]*:[[:space:]]*"[a-z]+"' | head -1 | sed -E 's/.*"([a-z]+)"$/\1/' || true)

case "$status" in
    identical|behind)
        echo "check-inspektor-gadget-pin: confirmed ${pinned_commit} is an ancestor of (or equal to) ${GUARDED_FORK}:main (status=${status})."
        echo "check-inspektor-gadget-pin: PASS"
        exit 0
        ;;
    ahead|diverged)
        echo "" >&2
        echo "check-inspektor-gadget-pin: FAIL" >&2
        echo "" >&2
        echo "Commit ${pinned_commit} pinned in the ${TARGET_MODULE} replace" >&2
        echo "directive is NOT an ancestor of ${GUARDED_FORK}:main (compare" >&2
        echo "status=${status}). This looks like a pin at an unmerged branch" >&2
        echo "commit that was never re-pinned to the merged SHA." >&2
        echo "" >&2
        echo "Re-pin the replace directive to a commit that is actually on" >&2
        echo "${GUARDED_FORK}'s main branch before merging this PR." >&2
        exit 1
        ;;
    *)
        echo "check-inspektor-gadget-pin: WARNING - unexpected/empty response from GitHub compare API (got status='${status}'); response was:"
        echo "$compare_json" | head -c 500
        echo ""
        echo "check-inspektor-gadget-pin: not failing the build on an inconclusive network check; relying on signal 1 (NOTE marker check, which passed)."
        echo "check-inspektor-gadget-pin: PASS (best-effort ancestor check inconclusive, no NOTE marker found)"
        exit 0
        ;;
esac
