import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
EXPERIMENT = ROOT / 'docs/experiments/gvisor-start-integration-20261102'
sys.path.insert(0, str(EXPERIMENT))
spec = importlib.util.spec_from_file_location('integration_verifier', EXPERIMENT / 'verify.py')
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
sys.path.pop(0)


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.rows = json.loads((EXPERIMENT / 'evidence/runtime-ledger.json').read_text())
        self.events = [json.loads(line) for line in (EXPERIMENT / 'evidence/observations.jsonl').read_text().splitlines()]

    def raw(self):
        return b'\n'.join(json.dumps(event).encode() for event in self.events)

    def test_retained_evidence(self):
        result = verifier.verify(self.rows, self.raw(), b'')
        self.assertEqual(result, json.loads((EXPERIMENT / 'evidence/verification.json').read_text()))

    def test_missing_event(self):
        self.events.pop()
        with self.assertRaises(ValueError):
            verifier.verify(self.rows, self.raw(), b'')

    def test_uid_mismatch(self):
        self.events[0]['pod_uid'] = 'wrong'
        with self.assertRaises(ValueError):
            verifier.verify(self.rows, self.raw(), b'')

    def test_privacy_failures(self):
        for field, value in [('wire_canary_found', True), ('unexpected_attribute_count', 1)]:
            with self.subTest(field=field):
                events = copy.deepcopy(self.events)
                events[0][field] = value
                raw = b'\n'.join(json.dumps(event).encode() for event in events)
                with self.assertRaises(ValueError):
                    verifier.verify(self.rows, raw, b'')
        with self.assertRaises(ValueError):
            verifier.verify(self.rows, self.raw(), verifier.CANARY.encode())
        with self.assertRaises(ValueError):
            verifier.verify(self.rows, self.raw() + verifier.CANARY.encode(), b'')

    def test_no_overlap(self):
        parallel = [row for row in self.rows if row['name'].startswith('integration-parallel-')]
        parallel[1]['started_at'] = parallel[0]['finished_at']
        with self.assertRaises(ValueError):
            verifier.verify(self.rows, self.raw(), b'')

    def test_optimized_python_cannot_publish_failed_verification(self):
        self.events.pop()
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            (base / 'rows.json').write_text(json.dumps(self.rows))
            (base / 'events.jsonl').write_bytes(self.raw())
            program = """
import json,pathlib,sys
sys.path.insert(0,sys.argv[1])
import verify
base=pathlib.Path(sys.argv[2])
result=verify.verify(json.loads((base/'rows.json').read_text()),(base/'events.jsonl').read_bytes(),b'')
(base/'verification.json').write_text(json.dumps(result))
"""
            for optimized in (False, True):
                env = os.environ.copy()
                env.pop('PYTHONOPTIMIZE', None)
                if optimized:
                    env['PYTHONOPTIMIZE'] = '1'
                command = [sys.executable] + (['-O'] if optimized else [])
                result = subprocess.run(command + ['-c', program, str(EXPERIMENT), str(base)],
                                        env=env, capture_output=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((base / 'verification.json').exists())


if __name__ == '__main__':
    unittest.main()
