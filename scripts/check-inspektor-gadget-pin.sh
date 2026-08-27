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
#   1. A `NOTE:` comment immediately above the replace line is treated as an
#      explicit, self-declared "this is a temporary pin, do not merge yet"
#      marker. Its mere presence (the whole word NOTE, case-insensitive) is an
#      automatic hard failure -- the block of commentary immediately preceding
#      this one replace line is dedicated to it, so a NOTE there is already
#      unambiguous; no further wording is required. This is the PRIMARY
#      check: it is deterministic, requires no network access, and cannot be
#      defeated by network flakiness or the target repo being private/
#      rate-limited. It relies on the convention that whoever does a
#      temporary "stack immediately" repoint of this replace line adds such
#      a comment.
#
#   2. A best-effort ancestor check against kubescape/inspektor-gadget:main
#      via the GitHub REST "compare" API (authenticated with GITHUB_TOKEN
#      when available, so a private repo or visibility change doesn't turn
#      into an unauthenticated 404). This is DEFENSE IN DEPTH for the case
#      where the NOTE comment is stripped without the pin actually having
#      been updated to a merged commit. It is deliberately best-effort: if
#      the network call fails, times out, or the repo/commit can't be reached
#      (e.g. CI runner has no egress, GitHub API rate limit, repo visibility
#      changes, or the caller isn't authorized to read it -- which surfaces
#      as HTTP 404, indistinguishable from "commit doesn't exist"), this
#      script WARNS but does not fail the build on that alone -- a flaky
#      network check would make this gate itself unreliable, which is worse
#      than not having signal #2 at all. It only hard-fails when the API
#      gives a definitive, unambiguous answer: HTTP 422 (malformed/unknown
#      ref on a repo we *can* read), or compare status "ahead"/"diverged"
#      (the pinned commit is real but not on main).
#
#      Note: `git ls-remote` alone cannot answer an ancestor question (it
#      only maps refs to their tip SHA, not arbitrary-commit ancestry), so
#      the GitHub compare API is used instead -- it answers the actual
#      question directly without needing a full/shallow clone of the fork.
#
# Usage:
#   scripts/check-inspektor-gadget-pin.sh [path/to/go.mod]
#
# Environment:
#   GITHUB_TOKEN - optional. When set, sent as a Bearer auth header on the
#                  compare API call so a private guarded fork (or one whose
#                  visibility just changed) resolves instead of 404-ing.
#                  Safe to leave unset -- the header is simply omitted, and
#                  the call proceeds unauthenticated as before.
#
# Exit codes:
#   0 - OK (no replace directive found, or it passed both checks)
#   1 - FAIL (NOTE marker present, commit confirmed not merged to main, or
#       the replace directive is present but in a format this script could
#       not parse)
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

# Find the line number of the replace directive for the guarded module. This
# matches both the single-line form:
#   replace github.com/inspektor-gadget/inspektor-gadget => ... v0.0.0-...
# and a line inside a block form:
#   replace (
#       github.com/inspektor-gadget/inspektor-gadget => ... v0.0.0-...
#   )
# -- i.e. an optional "replace" keyword, optional leading whitespace, then the
# target module and "=>".
ESCAPED_TARGET="${TARGET_MODULE//./\\.}"
replace_line_no=$(grep -nE "^[[:space:]]*(replace[[:space:]]+)?${ESCAPED_TARGET}[[:space:]]*=>" "$GOMOD" | head -1 | cut -d: -f1 || true)

if [[ -z "$replace_line_no" ]]; then
    # The module might still be present in go.mod in some form this script's
    # regex above doesn't recognize (e.g. a go.mod syntax variant it wasn't
    # written to expect). Silently passing in that case would defeat the
    # whole point of a mechanical guard, so treat "the module string is here,
    # but not where we expect it" as a loud failure rather than a pass.
    if grep -qF "$TARGET_MODULE" "$GOMOD"; then
        echo "" >&2
        echo "check-inspektor-gadget-pin: FAIL" >&2
        echo "" >&2
        echo "'${TARGET_MODULE}' appears in ${GOMOD}, but this script could not find it" >&2
        echo "as a recognizable 'replace' directive (neither the single-line form nor a" >&2
        echo "line inside a 'replace ( ... )' block)." >&2
        echo "" >&2
        echo "This script does not know how to parse the current go.mod format for this" >&2
        echo "directive and needs to be updated -- refusing to silently pass rather than" >&2
        echo "risk missing a stale pin." >&2
        exit 1
    fi

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
# comment line), then look for a NOTE marker inside that block. This also
# works correctly for a replace line inside a `replace ( ... )` block: if the
# preceding line is another replace entry (or the `replace (` opener) rather
# than a comment, the walk stops immediately and comment_block stays empty,
# same as "no NOTE marker" for the single-line form.
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

if echo "$comment_block" | grep -qiw 'NOTE'; then
    echo "" >&2
    echo "check-inspektor-gadget-pin: FAIL" >&2
    echo "" >&2
    echo "A NOTE comment above the ${TARGET_MODULE} replace directive marks" >&2
    echo "this pin as temporary:" >&2
    echo "" >&2
    echo "$comment_block" | sed 's/^/  /' >&2
    echo "" >&2
    echo "This PR must not merge with that marker still in place. Re-pin the" >&2
    echo "replace directive to the merged commit SHA on the target fork's" >&2
    echo "main branch, then remove the NOTE comment." >&2
    exit 1
fi

# --- Signal 2: best-effort ancestor check against kubescape/inspektor-gadget:main ---
#
# Only meaningful when the replace target is the guarded fork; other forks
# (e.g. a developer's personal fork used for short-lived iteration) are not
# in scope for this specific safeguard.
replace_module=$(echo "$replace_line" | sed -E 's/^[[:space:]]*(replace[[:space:]]+)?[^[:space:]]+[[:space:]]*=>[[:space:]]*([^[:space:]]+).*/\2/')
replace_version=$(echo "$replace_line" | sed -E 's/^[[:space:]]*(replace[[:space:]]+)?[^[:space:]]+[[:space:]]*=>[[:space:]]*[^[:space:]]+[[:space:]]+([^[:space:]]+).*/\2/')

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

# Authenticate when GITHUB_TOKEN is available so a private guarded fork (or
# one whose visibility just changed) resolves instead of 404-ing. The header
# is only added when a token is actually present: unlike an absent header,
# sending "Authorization: Bearer" with an empty value is NOT treated by
# GitHub as an unauthenticated request -- it responds 401 "Bad credentials"
# instead, which would turn every run without a token into a spurious
# inconclusive result.
curl_auth_args=()
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    curl_auth_args=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
fi

compare_response=$(curl -sS --max-time 10 \
    -H "Accept: application/vnd.github+json" \
    "${curl_auth_args[@]}" \
    -w $'\n%{http_code}' \
    "${GUARDED_FORK_API}/compare/main...${pinned_commit}" 2>/dev/null) || compare_response=""

if [[ -z "$compare_response" ]]; then
    echo "check-inspektor-gadget-pin: WARNING - could not reach GitHub API to verify ancestry (network issue, rate limit, or private repo without auth). Not failing the build on this alone; relying on signal 1 (NOTE marker check, which passed)."
    echo "check-inspektor-gadget-pin: PASS (best-effort ancestor check inconclusive, no NOTE marker found)"
    exit 0
fi

http_code="${compare_response##*$'\n'}"
compare_json="${compare_response%$'\n'*}"

# Only HTTP 422 is a DEFINITIVE answer here -- it means GitHub could read the
# repo and tells us the ref is malformed/unknown (a typo'd hash, a commit
# that was never pushed, or an invalid ref). Fail hard on that rather than
# letting it fall into the generic "unexpected response" WARN+PASS branch
# below, which would let a clearly-bogus pin slip through as merely
# inconclusive.
#
# HTTP 404 is deliberately NOT treated as definitive: GitHub returns 404, not
# 403, for any repository the caller cannot read -- a private repo and an
# unauthenticated read of a repo whose visibility just changed both land
# here, indistinguishable from "commit doesn't exist". Hard-failing on a 404
# would contradict this script's own policy of warning (not failing) on
# "repo can't be reached" conditions, so it falls through to the WARN+PASS
# branch below, alongside other non-definitive codes (403 rate-limit, 5xx,
# timeouts, etc.).
case "$http_code" in
    422)
        echo "" >&2
        echo "check-inspektor-gadget-pin: FAIL" >&2
        echo "" >&2
        echo "GitHub returned HTTP 422 for:" >&2
        echo "  ${GUARDED_FORK_API}/compare/main...${pinned_commit}" >&2
        echo "-- the pinned commit does not exist on ${GUARDED_FORK} (a typo'd hash, a" >&2
        echo "commit that was never pushed, or an invalid ref). A pin that can't even be" >&2
        echo "resolved is not a valid pin." >&2
        echo "" >&2
        echo "Re-pin the replace directive to a real commit on ${GUARDED_FORK}'s main branch." >&2
        exit 1
        ;;
    404)
        echo "check-inspektor-gadget-pin: WARNING - GitHub returned HTTP 404 for the compare API call. This is not a definitive 'commit does not exist' answer -- GitHub returns 404 (not 403) for any repository the caller cannot read, which a private ${GUARDED_FORK} or an unauthenticated read of a repo whose visibility just changed would also produce. Not failing the build on this alone; relying on signal 1 (NOTE marker check, which passed)."
        echo "check-inspektor-gadget-pin: PASS (best-effort ancestor check inconclusive, no NOTE marker found)"
        exit 0
        ;;
esac

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
