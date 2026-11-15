import copy
import json
import pathlib
import struct
import unittest

from analyze import analyze, exit_code, load, rfc3339_ns
from trial import CANARY, decode, fields, varint

EVIDENCE = pathlib.Path(__file__).parent / 'evidence'
RUNS = sorted(p for p in EVIDENCE.iterdir() if p.is_dir() and p.name.startswith('run-'))


def number(value):
    value &= (1 << 64) - 1
    out = bytearray()
    while value >= 128:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def blob(field, value):
    return number(field * 8 + 2) + number(len(value)) + value


def scalar(field, value):
    return number(field * 8) + number(value)


def context(tid, tg, start, cid):
    return (scalar(1, 100) + scalar(2, tid) + scalar(3, start) + scalar(4, tg) + scalar(5, start)
            + blob(6, cid) + blob(8, CANARY.encode()) + blob(9, CANARY.encode()))


class DecodeTests(unittest.TestCase):
    def test_exit_keeps_start_times_and_drops_sensitive_context(self):
        frame = struct.pack('<HHI', 8, 5, 0) + blob(1, context(2, 2, 555, b'a' * 64)) + scalar(2, 7 << 8)
        row = decode(frame, connection=3)
        self.assertEqual((row['kind'], row['thread_group_id'], row['thread_group_start_time_ns'],
                          row['thread_start_time_ns'], row['wait_status'], row['connection']),
                         ('task_exit', 2, 555, 555, 1792, 3))
        self.assertNotIn(CANARY, json.dumps(row))

    def test_negative_int32_status_is_sign_extended(self):
        frame = struct.pack('<HHI', 8, 4, 0) + blob(1, context(2, 2, 1, b'c' * 64)) + scalar(2, -1)
        self.assertEqual(decode(frame)['wait_status'], -1)

    def test_start_discards_sensitive_unknown_fields(self):
        payload = blob(1, context(2, 2, 9, b'b' * 64)) + blob(2, b'b' * 64) + blob(3, CANARY.encode()) + blob(4, CANARY.encode())
        row = decode(struct.pack('<HHI', 8, 1, 0) + payload)
        self.assertNotIn(CANARY, json.dumps(row))
        self.assertEqual(row['container_id'], 'b' * 64)

    def test_malformed_input_and_other_points(self):
        for data in [b'\x12\xff', b'\x12\x05x', b'\x00', b'\x0b']:
            with self.subTest(data=data), self.assertRaises(ValueError):
                list(fields(data))
        with self.assertRaises(ValueError):
            varint(b'\xff' * 10, 0)
        with self.assertRaises(ValueError):
            decode(struct.pack('<HHI', 8, 5, 0) + blob(1, blob(6, b'not-an-id')))
        with self.assertRaises(ValueError):
            decode(struct.pack('<HHI', 20, 5, 0))
        self.assertIsNone(decode(struct.pack('<HHI', 8, 10, 0)))


class MappingTests(unittest.TestCase):
    def test_wait_status_to_cri_exit_code(self):
        self.assertEqual([exit_code(s) for s in (7 << 8, 0, 9, 15, 13 << 8)], [7, 0, 137, 143, 13])

    def test_rfc3339_offsets(self):
        self.assertEqual(rfc3339_ns('2026-11-11T16:05:18.201019016+05:30'),
                         rfc3339_ns('2026-11-11T10:35:18.201019016Z'))


class EvidenceTests(unittest.TestCase):
    def test_retained_runs_agree_with_cri(self):
        self.assertEqual(len(RUNS), 3)
        for run in RUNS:
            with self.subTest(run=run.name):
                result = analyze(*load(run))
                self.assertEqual(result['terminal_observed'], result['terminal_agrees_with_cri'])
                self.assertEqual(result['terminal_missing_expected_loss'], 2)
                self.assertTrue(result['exec_session_exit_left_container_running'])
                self.assertEqual(result, json.loads((run / 'summary.json').read_text()))

    def test_status_mismatch_and_extra_fields_fail(self):
        rows, events, counters = load(RUNS[0])
        bad = copy.deepcopy(events)
        next(e for e in bad if e['kind'] == 'task_exit' and e['thread_group_id'] == 2)['wait_status'] = 0
        with self.assertRaises(ValueError):
            analyze(rows, bad, counters)
        bad = copy.deepcopy(events)
        bad[0]['process_name'] = CANARY
        with self.assertRaises(ValueError):
            analyze(rows, bad, counters)
        with self.assertRaises(ValueError):
            analyze(rows[:-1], events, counters)

    def test_wrong_start_time_is_not_a_terminal_candidate(self):
        rows, events, counters = load(RUNS[0])
        bad = copy.deepcopy(events)
        cid = rows[0]['container_id']
        for e in bad:
            if e['kind'] in ('task_exit', 'exit_notify_parent') and e.get('context_container_id') == cid \
                    and e['thread_group_id'] == 2:
                e['thread_group_start_time_ns'] += 1
        with self.assertRaises(ValueError):
            analyze(rows, bad, counters)


if __name__ == '__main__':
    unittest.main()
