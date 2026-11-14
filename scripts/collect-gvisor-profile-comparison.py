#!/usr/bin/env python3
"""Read-only collector for the controlled K3s ordinary/gVisor experiment.

LIST discovers profile names only. Individual GETs supply profile bodies.
Export booleans/counts, never raw profile args, logs or Kubernetes credentials.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import sys


RESOURCE = "containerprofiles.spdx.softwarecomposition.kubescape.io"
INSTANCE = "kubescape.io/instance-id"


class InvalidComparison(ValueError):
    pass


def command_json(args):
    result = subprocess.run(args, capture_output=True, timeout=30, check=False)
    if result.returncode:
        # stderr may contain arbitrary API data. Do not copy it into evidence.
        raise InvalidComparison("comparison query failed")
    try:
        return json.loads(result.stdout)
    except ValueError:
        raise InvalidComparison("comparison query returned invalid JSON") from None


def collect(namespace, ordinary, gvisor, query=command_json):
    for value in (namespace, ordinary, gvisor):
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", value):
            raise InvalidComparison("use simple DNS labels for experiment names")
    if ordinary == gvisor:
        raise InvalidComparison("comparison requires two distinct Pods")
    kubectl = ["k3s", "kubectl", "--request-timeout=20s", "-n", namespace]
    report = {"recorded_at": datetime.now(timezone.utc).isoformat(),
              "namespace": namespace, "pods": [], "profiles": []}
    instances = {}
    created = {}
    for name, runtime in ((ordinary, "io.containerd.runc.v2"),
                          (gvisor, "io.containerd.runsc.v1")):
        pod = query(kubectl + ["get", "pod", name, "-o", "json"])
        if pod["metadata"]["name"] != name or pod["metadata"]["namespace"] != namespace:
            raise InvalidComparison("Pod identity mismatch")
        spec = pod["spec"]["containers"]
        statuses = pod["status"].get("containerStatuses", [])
        if len(spec) != 1 or len(statuses) != 1 or statuses[0]["name"] != spec[0]["name"]:
            raise InvalidComparison("experiment requires one application container per Pod")
        status = statuses[0]
        end = status.get("state", {}).get("terminated", {})
        if end.get("exitCode") != 0 or not end.get("startedAt") or not end.get("finishedAt"):
            raise InvalidComparison("both experiment workloads must have completed successfully")
        container_id = status["containerID"].removeprefix("containerd://")
        if not re.fullmatch(r"[a-f0-9]{64}", container_id):
            raise InvalidComparison("unexpected runtime container ID")
        info = query(["k3s", "ctr", "-n", "k8s.io", "containers", "info", container_id])
        if info["ID"] != container_id or info["Runtime"]["Name"] != runtime:
            raise InvalidComparison("independent containerd runtime check failed")
        if query(kubectl + ["logs", name]) != {"completed": True}:
            raise InvalidComparison("workload completion marker missing")
        instances[name] = ("apiVersion-v1/namespace-" + namespace +
                           "/kind-Pod/name-" + name + "/containerName-" + spec[0]["name"])
        created[name] = datetime.fromisoformat(pod["metadata"]["creationTimestamp"].replace("Z", "+00:00"))
        report["pods"].append({"name": name, "uid": pod["metadata"]["uid"],
                               "container_id": container_id, "runtime": runtime,
                               "image_id": status["imageID"], "exit_code": 0, "completion_marker": True,
                               "started_at": end["startedAt"], "finished_at": end["finishedAt"]})

    listed = query(kubectl + ["get", RESOURCE, "-o", "json"])
    for item in listed["items"]:
        meta = item["metadata"]
        instance = meta.get("annotations", {}).get(INSTANCE)
        names = [name for name, expected in instances.items() if instance == expected]
        if not names:
            continue
        # Never use the LIST object's Spec as behavioral evidence.
        full = query(kubectl + ["get", RESOURCE, meta["name"], "-o", "json"])
        fetched = full["metadata"]
        if (fetched["name"] != meta["name"] or fetched["uid"] != meta["uid"] or
                fetched["namespace"] != namespace or
                fetched.get("annotations", {}).get(INSTANCE) != instance):
            raise InvalidComparison("profile changed identity during collection")
        profile_created = datetime.fromisoformat(fetched["creationTimestamp"].replace("Z", "+00:00"))
        if profile_created < created[names[0]]:
            raise InvalidComparison("use fresh Pod names; profile predates this Pod")
        execs = full.get("spec", {}).get("execs") or []
        report["profiles"].append({
            "name": fetched["name"], "uid": fetched["uid"], "pod": names[0],
            "query": "individual GET", "exec_entry_count": len(execs),
            "target_exec_present": any(e.get("path") == "/bin/busybox" and
                                       e.get("args") == ["/bin/busybox", "true"] for e in execs),
            "list_exec_entry_count": len(item.get("spec", {}).get("execs") or [])})
    ordinary_seen = any(p["pod"] == ordinary and p["target_exec_present"] for p in report["profiles"])
    gvisor_seen = any(p["pod"] == gvisor and p["target_exec_present"] for p in report["profiles"])
    report["ordinary_positive_control"] = ordinary_seen
    report["gvisor_target_exec_observed"] = gvisor_seen
    report["result"] = ("ordinary target observed; gVisor target not observed in profile path"
                        if ordinary_seen and not gvisor_seen else "inconclusive")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--ordinary-pod", required=True)
    parser.add_argument("--gvisor-pod", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        report = collect(args.namespace, args.ordinary_pod, args.gvisor_pod)
        with Path(args.output).open("x") as output:
            json.dump(report, output, indent=2)
            output.write("\n")
        if not report["ordinary_positive_control"]:
            print("ordinary positive control failed; evidence is inconclusive", file=sys.stderr)
            return 1
        return 0
    except (ValueError, KeyError, TypeError, OSError, subprocess.TimeoutExpired):
        print("comparison collection failed; no visibility conclusion", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
