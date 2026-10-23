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

    def test_canary_alphabet_rejects_json_escaped_markers(self):
        artifact = self.root / "retained.json"
        self.run_check()
        for suffix in ['"', "\\", "\n", "\t", " ", "é"]:
            canary = "A" * 15 + suffix
            artifact.write_text(json.dumps({"argv": [canary]}))
            with self.subTest(suffix=suffix), self.assertRaises(trial.InvalidEvidence):
                trial.check(self.expected, self.events, canary, [artifact])

    def test_invalid_canary_in_matching_escaped_identities(self):
        for suffix in ['"', "\\"]:
            canary = "A" * 15 + suffix
            self.expected.write_text(json.dumps({canary: 1}))
            self.events.write_text(json.dumps(dict(self.records[0], ContainerID=canary)))
            with self.subTest(suffix=suffix), self.assertRaisesRegex(trial.InvalidEvidence, "use a synthetic canary"):
                trial.check(self.expected, self.events, canary)

    def test_supported_canary_alphabet(self):
        self.run_check()
        for canary in ["aZ09_-" * 3, "A" * 16]:
            with self.subTest(canary=canary):
                self.assertEqual(trial.check(self.expected, self.events, canary), 2)
        with self.assertRaises(trial.InvalidEvidence):
            trial.check(self.expected, self.events, "A" * 15)

    def test_literal_canary_in_json_artifact_is_rejected(self):
        artifact = self.root / "retained.json"
        artifact.write_text(json.dumps({"argv": [CANARY]}))
        with self.assertRaises(trial.InvalidEvidence):
            self.run_check(artifacts=[artifact])

    def test_escaped_identity_canary_is_rejected(self):
        # Exercise decoded checks even when every marker byte is JSON-escaped.
        escaped = "".join("\\u%04x" % ord(char) for char in CANARY)
        self.expected.write_text(json.dumps({CANARY: 1}).replace(CANARY, escaped))
        self.events.write_text(json.dumps(dict(self.records[0], ContainerID=CANARY)).replace(CANARY, escaped))
        with self.assertRaises(trial.InvalidEvidence):
            trial.check(self.expected, self.events, CANARY)
        # A marker in an event also fails if it is absent from the manifest.
        self.expected.write_text(json.dumps({"first": 1}))
        with self.assertRaisesRegex(trial.InvalidEvidence, "privacy canary"):
            trial.check(self.expected, self.events, CANARY)

    def test_canary_validation_does_not_echo_marker(self):
        canary = "A" * 15 + '"'
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            status = trial.main(["--expected", str(self.expected), "--events", str(self.events), "--canary", canary])
        self.assertEqual(status, 1)
        self.assertNotIn(canary, output.getvalue())
        self.assertIn("canary", output.getvalue())

    def test_blank_records_fail_but_final_newline_is_valid(self):
        self.run_check()
        records = self.events.read_text()
        for contents in ["\n" + records, records.replace("\n", "\n\n"), records + "\n \t\n"]:
            self.events.write_text(contents)
            with self.subTest(contents=contents), self.assertRaises(trial.InvalidEvidence):
                trial.check(self.expected, self.events, CANARY)
        self.events.write_text(records + "\n")
        self.assertEqual(trial.check(self.expected, self.events, CANARY), 2)

    def test_timestamp_offsets(self):
        for offset in ["+00:60", "-00:60", "+24:00", "+12:99"]:
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                self.run_check([dict(self.records[0], ObservedAt="2026-10-22T10:00:00" + offset), self.records[1]])
        for offset in ["Z", "+00:00", "-05:30", "+23:59"]:
            with self.subTest(offset=offset):
                self.assertEqual(self.run_check([dict(self.records[0], ObservedAt="2026-10-22T10:00:00.123456789" + offset), self.records[1]]), 2)

    def test_invalid_expected_counts(self):
        for expected in [{}, {"first": 0}, {"first": True}, {"first": -1}]:
            self.expected.write_text(json.dumps(expected))
            with self.subTest(expected=expected), self.assertRaises(trial.InvalidEvidence):
                self.run_check()


if __name__ == "__main__":
    unittest.main()
