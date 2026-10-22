import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("trial", Path(__file__).with_name("check-gvisor-start-trial.py"))
trial = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trial)
CANARY = "GVS_TRIAL_CANARY_2026"


class TrialCheckTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.expected = self.root / "expected.json"
        self.events = self.root / "events.jsonl"
        self.expected.write_text(json.dumps({"first": 1, "second": 1}))
        self.records = [dict(Source="gvisor_trace", ContainerID=id,
                             ObservedAt="2026-10-22T10:00:00.123456789Z", Dropped=0)
                        for id in ["first", "second"]]

    def run_check(self, records=None, artifacts=()):
        self.events.write_text("\n".join(json.dumps(record) for record in
                                        (self.records if records is None else records)))
        return trial.check(self.expected, self.events, CANARY, artifacts)

    def test_two_identities_and_twenty_starts(self):
        self.assertEqual(self.run_check(), 2)
        self.expected.write_text(json.dumps({str(i): 1 for i in range(20)}))
        self.assertEqual(self.run_check([dict(self.records[0], ContainerID=str(i)) for i in range(20)]), 20)

    def test_missing_duplicate_and_unknown_starts(self):
        for records in [[], self.records[:1], self.records + self.records[:1],
                        [dict(self.records[0], ContainerID="unknown")]]:
            with self.subTest(records=len(records)), self.assertRaises(trial.InvalidEvidence):
                self.run_check(records)

    def test_source_loss_timestamp_and_unexpected_fields(self):
        for update in [dict(Source="ebpf"), dict(Dropped=1), dict(Dropped=True),
                       dict(ObservedAt="2026-10-22T10:00:00"), dict(Args=["harmless"]),
                       dict(ContainerID=["first"])]:
            with self.subTest(update=update), self.assertRaises(trial.InvalidEvidence):
                self.run_check([dict(self.records[0], **update), self.records[1]])

    def test_privacy_marker_in_additional_artifact(self):
        artifact = self.root / "stderr.txt"
        artifact.write_text(CANARY)
        with self.assertRaises(trial.InvalidEvidence):
            self.run_check(artifacts=[artifact])

    def test_no_payload_in_failure_diagnostics(self):
        for payload in [CANARY, '{"Args":"' + CANARY + '"}',
                        '{"Source":"gvisor_trace","Source":"ebpf"}',
                        json.dumps(dict(self.records[0], ContainerID=CANARY))]:
            self.events.write_text(payload)
            output = io.StringIO()
            with contextlib.redirect_stderr(output):
                self.assertEqual(trial.main(["--expected", str(self.expected), "--events", str(self.events), "--canary", CANARY]), 1)
            self.assertNotIn(CANARY, output.getvalue())
            self.assertNotIn(payload, output.getvalue())

    def test_invalid_expected_counts(self):
        for expected in [{}, {"first": 0}, {"first": True}, {"first": -1}]:
            self.expected.write_text(json.dumps(expected))
            with self.subTest(expected=expected), self.assertRaises(trial.InvalidEvidence):
                self.run_check()


if __name__ == "__main__":
    unittest.main()
