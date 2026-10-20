#!/usr/bin/env python3
"""Check local reusable workflow ceilings and release/CodeQL token scopes.

Requires PyYAML. Run from any directory; optionally pass a repository root.
This validates declarations, not GitHub's runtime token policy or secrets.
"""

import sys
from pathlib import Path

import yaml


SCOPES = set("""
actions artifact-metadata attestations checks contents deployments discussions
id-token issues models packages pages pull-requests security-events statuses
""".split())
LEVELS = {"none": 0, "read": 1, "write": 2}

# These operations must remain possible without granting unrelated scopes.
CODEQL = {"contents": "read", "actions": "read", "security-events": "write"}
BENCHMARK = {"contents": "read", "pull-requests": "write"}
RELEASE = {
    "contents": "write", "id-token": "write", "pull-requests": "write",
    "artifact-metadata": "write", "attestations": "write",
}
REQUIRED = {
    ("pr-created.yaml", "pr-created"): CODEQL,
    ("incluster-comp-pr-created.yaml", "test"): CODEQL,
    ("go-basic-tests.yaml", "Environment-Test"): CODEQL,
    ("go-basic-tests.yaml", "Check-secret"): {},
    ("pr-merged.yaml", "pr-merged"): RELEASE,
    ("bypass.yaml", "pr-merged"): RELEASE,
    ("incluster-comp-pr-merged.yaml", "docker-build"): {
        "contents": "read", "id-token": "write",
        "artifact-metadata": "write", "attestations": "write",
    },
    ("incluster-comp-pr-merged.yaml", "run-tests"): {},
    ("incluster-comp-pr-merged.yaml", "create-release-and-retag"): {
        "contents": "write",
    },
    ("incluster-comp-pr-merged.yaml", "benchmark"): BENCHMARK,
    ("benchmark.yaml", "benchmark"): BENCHMARK,
}


def expand(value):
    if value == "read-all":
        return {scope: (0 if scope == "id-token" else 1) for scope in SCOPES}
    if not isinstance(value, dict):
        raise ValueError(f"expected explicit permissions, got {value!r}")
    for scope, level in value.items():
        if scope not in SCOPES or level not in LEVELS:
            raise ValueError(f"unsupported permission: {scope}: {level}")
    return {scope: LEVELS.get(value.get(scope), 0) for scope in SCOPES}


def check(root):
    directory = root / ".github/workflows"
    # BaseLoader preserves the GitHub Actions key 'on' as a string (YAML 1.2).
    workflows = {
        path.name: yaml.load(path.read_text(), Loader=yaml.BaseLoader)
        for path in sorted(directory.iterdir())
        if path.suffix in (".yaml", ".yml")
    }
    if not workflows:
        raise ValueError(f"no workflows found in {directory}")
    for name, workflow in workflows.items():
        if any(level > 1 for level in expand(workflow.get("permissions")).values()):
            raise ValueError(f"{name}: workflow default must be read-only")
    for (name, job), expected in REQUIRED.items():
        actual = workflows[name]["jobs"][job].get("permissions")
        if actual != expected:
            raise ValueError(f"{name}/{job}: expected {expected}, got {actual}")

    edges = set()

    def within(requested, ceiling, location):
        for scope, level in expand(requested).items():
            if level > ceiling[scope]:
                raise ValueError(f"{location}: {scope} exceeds caller ceiling")

    def visit(name, ceiling=None, stack=()):
        if name in stack:
            raise ValueError(f"cyclic workflow call: {' -> '.join((*stack, name))}")
        workflow = workflows[name]
        defaults = workflow["permissions"]
        route = " -> ".join((*stack, name))
        if ceiling is not None:
            # Validate workflow defaults too, even when all jobs override them.
            within(defaults, ceiling, f"{route} defaults")
        for job_id, job in workflow["jobs"].items():
            permissions = job.get("permissions", defaults)
            if ceiling is not None:
                within(permissions, ceiling, f"{route}/{job_id}")
            target = job.get("uses", "")
            if target.startswith("./.github/workflows/"):
                callee = target.removeprefix("./.github/workflows/")
                edges.add((name, job_id, callee))
                visit(callee, expand(permissions), (*stack, name))

    # Check every workflow as an entrypoint, and traverse every nested path.
    # Conditions are deliberately ignored: skipped jobs still need valid scopes.
    for name in workflows:
        visit(name)
    for caller, job, callee in sorted(edges):
        print(f"PASS {caller}/{job} -> {callee} (defaults and jobs)")
    print(f"PASS {len(workflows)} read-only defaults; {len(edges)} local call edges; "
          f"{len(REQUIRED)} operation permission maps")


if __name__ == "__main__":
    try:
        check(Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1])
    except (KeyError, ValueError, yaml.YAMLError) as error:
        sys.exit(f"FAIL {error}")
