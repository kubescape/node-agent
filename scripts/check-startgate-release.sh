#!/usr/bin/env bash
#
# check-startgate-release.sh
#
# Release gate for the NRI start gate (pkg/sandboxpolicy/startgate). The
# start gate must not be runnable in a published image before its
# qualification slice (S9) merges: the Go constant startGateBuildable is
# false, and the test-only build tag startgate_vmtest (which sets it true)
# must never reach a release build. This script is the pipeline half of
# that rule. build/Dockerfile runs it on the binaries the image ships, in
# the builder stage, before they are copied into the image.
#
# Usage:
#   scripts/check-startgate-release.sh --tags <tags|none> [--binaries-only]
#       <binary>... [--without-startgate <binary>]...
#
#   --tags               the exact -tags the release build used ("none" for
#                        no tags). Required.
#   <binary>             a release binary that links the start gate (e.g.
#                        node-agent). At least one is required.
#   --without-startgate  a release binary that does not link the start gate
#                        (e.g. sbom-scanner).
#   --binaries-only      skip the source-tree checks (rules 4 and 5); the
#                        binary checks (rules 1 to 3) always run.
#
# It fails (exit 1) when:
#   1. --tags, or every start-gate binary, is missing;
#   2. the declared tags, or GOFLAGS, carry startgate_vmtest;
#   3. a binary's own content says the gate is buildable:
#      - it contains the marker kubescape-startgate-buildable=true
#        (pkg/sandboxpolicy/startgate buildMarker, derived at compile time
#        from startGateBuildable; it survives -ldflags='-s -w' and cross
#        builds), or
#      - a start-gate binary lacks the marker kubescape-startgate-buildable=false,
#        or a --without-startgate binary carries either marker, or
#      - its recorded -tags (go version -m) differ from the declared ones or
#        carry startgate_vmtest, or its build info cannot be read;
#   4. (tree) under the declared tags, pkg/sandboxpolicy/startgate does not
#      compile buildable.go, or compiles buildable_vmtest.go, or buildable.go
#      does not declare `const startGateBuildable = false`;
#   5. (tree) under the declared tags, startgate.Buildable() is not proven
#      false at run time (TestS5DefaultBuildNeverDials must run and pass).
# S9 is the only change allowed to relax this script.
set -u
cd "$(dirname "$0")/.." || exit 1
fail=0
bad() { echo "FAIL: $*"; fail=1; }
tags="" tagsSet=0 treeChecks=1
bins=() without=()
while [ $# -gt 0 ]; do
	case "$1" in
	--tags)
		[ $# -ge 2 ] || { echo "FAIL: --tags needs a value"; exit 1; }
		tags=$2 tagsSet=1
		shift 2
		;;
	--without-startgate)
		[ $# -ge 2 ] || { echo "FAIL: --without-startgate needs a binary"; exit 1; }
		without+=("$2")
		shift 2
		;;
	--binaries-only)
		treeChecks=0
		shift
		;;
	*)
		bins+=("$1")
		shift
		;;
	esac
done
[ $tagsSet -eq 1 ] || { echo "FAIL: --tags <tags|none> is required"; exit 1; }
[ ${#bins[@]} -gt 0 ] || { echo "FAIL: at least one release binary that links the start gate is required"; exit 1; }
[ "$tags" = none ] && tags=""
want=$(echo "${tags//,/ }" | tr ' ' '\n' | sed '/^$/d' | sort | paste -sd, -)
case ",$want,$(go env GOFLAGS)," in
*startgate_vmtest*) bad "the release build carries the test-only tag startgate_vmtest (tags [$want], GOFLAGS [$(go env GOFLAGS)])" ;;
esac
TRUE=kubescape-startgate-buildable=true
FALSE=kubescape-startgate-buildable=false
checkbin() { # binary, links the start gate (1) or not (0)
	local bin=$1 links=$2 info got
	[ -f "$bin" ] || { bad "$bin: no such binary"; return; }
	if grep -q -a -F "$TRUE" "$bin"; then bad "$bin carries $TRUE: the start gate is buildable in it"; fi
	if [ "$links" = 1 ]; then
		grep -q -a -F "$FALSE" "$bin" || bad "$bin lacks $FALSE: it does not prove the start gate is off"
	else
		if grep -q -a -F "$FALSE" "$bin"; then bad "$bin was declared without the start gate but links it"; fi
	fi
	if ! info=$(go version -m "$bin" 2>&1); then
		bad "$bin: cannot read its build info: $info"
		return
	fi
	got=$(echo "$info" | sed -nE 's/^[[:space:]]+build[[:space:]]+-tags=(.*)$/\1/p' | tr ',' '\n' | sed '/^$/d' | sort | paste -sd, -)
	echo "$bin: recorded tags [$got]"
	[ "$got" = "$want" ] || bad "$bin was built with tags [$got], not the declared [$want]"
	case ",$got," in *startgate_vmtest*) bad "$bin was built with startgate_vmtest" ;; esac
}
for bin in "${bins[@]}"; do checkbin "$bin" 1; done
for bin in "${without[@]}"; do checkbin "$bin" 0; done
if [ $treeChecks -eq 1 ]; then
	files=$(go list -tags "$want" -f '{{join .GoFiles " "}}' ./pkg/sandboxpolicy/startgate) || bad "go list failed"
	echo "startgate files under tags [$want]: $files"
	case " $files " in *" buildable.go "*) ;; *) bad "buildable.go is not compiled" ;; esac
	case " $files " in *" buildable_vmtest.go "*) bad "buildable_vmtest.go is compiled" ;; esac
	grep -qx 'const startGateBuildable = false' pkg/sandboxpolicy/startgate/buildable.go || bad "buildable.go does not declare the constant false"
	out=$(go test -count=1 -tags "$want" -v -run '^TestS5DefaultBuildNeverDials$' ./pkg/sandboxpolicy/startgate/ 2>&1)
	echo "$out" | grep -E -- '^(--- |ok|FAIL)' || true
	echo "$out" | grep -q -- '^--- PASS: TestS5DefaultBuildNeverDials ' || bad "startgate.Buildable() is not proven false under tags [$want]"
fi
[ $fail -eq 0 ] && echo "PASS: no release binary can run the start gate"
exit $fail
