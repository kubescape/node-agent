import copy
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("comparison", Path(__file__).with_name("collect-gvisor-profile-comparison.py"))
comparison = importlib.util.module_from_spec(spec)
spec.loader.exec_module(comparison)


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.queries = []
        self.runtime = {"a" * 64: "io.containerd.runc.v2", "b" * 64: "io.containerd.runsc.v1"}
        self.pods = {}
        for name, letter in (("ordinary", "a"), ("gvisor", "b")):
            self.pods[name] = {
                "metadata": {"name": name, "namespace": "trial", "uid": name,
                             "creationTimestamp": "2026-10-27T00:00:00Z"},
                "spec": {"containers": [{"name": "workload"}]},
                "status": {"containerStatuses": [{"name": "workload", "containerID": "containerd://" + letter * 64,
                           "imageID": "test-image", "state": {"terminated": {"exitCode": 0,
                           "startedAt": "2026-10-27T00:00:01Z", "finishedAt": "2026-10-27T00:02:00Z"}}}]}}
        self.full = {"metadata": {"name": "profile", "uid": "profile-uid", "namespace": "trial",
                     "creationTimestamp": "2026-10-27T00:00:02Z", "annotations": {
                     comparison.INSTANCE: "apiVersion-v1/namespace-trial/kind-Pod/name-ordinary/containerName-workload"}},
                     "spec": {"execs": [{"path": "/bin/busybox", "args": ["/bin/busybox", "true"]},
                                        {"path": "/private", "args": ["SYNTHETIC_SECRET_MUST_NOT_EXPORT"]}]}}
        self.listed = {"items": [{"metadata": copy.deepcopy(self.full["metadata"]), "spec": {"execs": None}}]}
        self.marker = {"completed": True}

    def query(self, args):
        self.queries.append(args)
        if args[1] == "ctr":
            return {"ID": args[-1], "Runtime": {"Name": self.runtime[args[-1]]}}
        if "logs" in args:
            return self.marker
        i = args.index("get")
        resource = args[i + 1]
        if resource == "pod":
            return self.pods[args[i + 2]]
        if args[i + 2] == "-o":
            return self.listed
        return self.full

    def collect(self):
        return comparison.collect("trial", "ordinary", "gvisor", self.query)

    def test_metadata_list_requires_individual_get(self):
        report = self.collect()
        self.assertTrue(report["ordinary_positive_control"])
        self.assertFalse(report["gvisor_target_exec_observed"])
        self.assertEqual(report["profiles"][0]["list_exec_entry_count"], 0)
        self.assertEqual(report["profiles"][0]["exec_entry_count"], 2)
        self.assertTrue(any("profile" in q for q in self.queries))
        self.assertNotIn("SYNTHETIC_SECRET", json.dumps(report))
        self.assertNotIn("/private", json.dumps(report))

    def test_list_payload_cannot_substitute_for_failed_get_control(self):
        self.listed["items"][0]["spec"] = copy.deepcopy(self.full["spec"])
        self.full["spec"]["execs"] = []
        report = self.collect()
        self.assertFalse(report["ordinary_positive_control"])
        self.assertEqual(report["result"], "inconclusive")

    def test_runtime_class_alone_is_not_runtime_verification(self):
        self.runtime["b" * 64] = "io.containerd.runc.v2"
        with self.assertRaises(comparison.InvalidComparison):
            self.collect()

    def test_failed_workload_cannot_establish_comparison(self):
        self.pods["ordinary"]["status"]["containerStatuses"][0]["state"]["terminated"]["exitCode"] = 1
        with self.assertRaises(comparison.InvalidComparison):
            self.collect()

    def test_successful_exit_without_marker_is_rejected(self):
        self.marker = {}
        with self.assertRaises(comparison.InvalidComparison):
            self.collect()

    def test_get_identity_must_match_list(self):
        self.full["metadata"]["uid"] = "replacement"
        with self.assertRaises(comparison.InvalidComparison):
            self.collect()

    def test_profile_from_previous_pod_is_rejected(self):
        self.full["metadata"]["creationTimestamp"] = "2026-10-26T00:00:00Z"
        with self.assertRaises(comparison.InvalidComparison):
            self.collect()

    def test_unrelated_profile_is_not_fetched(self):
        self.listed["items"][0]["metadata"]["annotations"][comparison.INSTANCE] = "unrelated"
        report = self.collect()
        self.assertFalse(report["ordinary_positive_control"])
        self.assertFalse(any("profile" in q for q in self.queries))


if __name__ == "__main__":
    unittest.main()
