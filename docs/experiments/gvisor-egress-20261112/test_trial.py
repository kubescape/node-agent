import copy
import json
import pathlib
import socket
import struct
import unittest

from analyze import load, summarize
from trial import CANARY, decode, fields, sockaddr, varint

EVIDENCE = pathlib.Path(__file__).parent / 'evidence'
RUNS = sorted(p for p in EVIDENCE.iterdir() if p.is_dir() and p.name.startswith('run-'))
NODE = '192.168.252.3'


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


def ctx(cid=b'a' * 64):
    return blob(1, scalar(2, 7) + scalar(4, 7) + blob(6, cid) + blob(8, CANARY.encode()) + blob(9, CANARY.encode()))


def inet(ip, port):
    return struct.pack('<H', socket.AF_INET) + struct.pack('>H', port) + socket.inet_aton(ip) + b'\0' * 8


class DecodeTests(unittest.TestCase):
    def test_connect_exit_keeps_destination_and_errno_only(self):
        payload = ctx() + blob(2, scalar(1, 0) + scalar(2, 115)) + scalar(4, 3) + blob(5, CANARY.encode()) \
            + blob(6, inet('192.0.2.10', 18083))
        row = decode(struct.pack('<HHI', 8, 10, 0) + payload, connection=2)
        self.assertEqual((row['kind'], row['phase'], row['errno'], row['fd'], row['connection']), ('connect', 'exit', 115, 3, 2))
        self.assertEqual(row['destination'], {'family': 'inet', 'port': 18083, 'address': '192.0.2.10'})
        self.assertNotIn(CANARY, json.dumps(row))

    def test_connect_enter_has_no_result(self):
        row = decode(struct.pack('<HHI', 8, 10, 0) + ctx() + blob(6, inet('10.0.0.1', 80)))
        self.assertEqual(row['phase'], 'enter')
        self.assertNotIn('result', row)

    def test_sockaddr_never_keeps_unix_paths(self):
        unix = struct.pack('<H', socket.AF_UNIX) + ('/run/' + CANARY).encode()
        self.assertEqual(sockaddr(unix), {'family': 'unix'})
        v6 = struct.pack('<H', socket.AF_INET6) + struct.pack('>H', 443) + b'\0' * 4 + socket.inet_pton(socket.AF_INET6, '2001:db8::1') + b'\0' * 4
        self.assertEqual(sockaddr(v6), {'family': 'inet6', 'port': 443, 'address': '2001:db8::1'})
        self.assertEqual(sockaddr(b'\x02'), {'family': 'invalid'})
        with self.assertRaises(ValueError):
            sockaddr(b'\0' * 129)

    def test_raw_points_keep_only_send_syscalls(self):
        sendto = ctx() + blob(2, scalar(1, 1)) + scalar(4, 206) + scalar(5, 3) + scalar(6, 0xdeadbeef)
        row = decode(struct.pack('<HHI', 8, 6, 0) + sendto)
        self.assertEqual((row['kind'], row['phase'], row['result']), ('sendto', 'exit', 1))
        self.assertNotIn('arg1', row)
        other = ctx() + scalar(4, 63)
        self.assertIsNone(decode(struct.pack('<HHI', 8, 6, 0) + other))
        self.assertIsNone(decode(struct.pack('<HHI', 8, 11, 0) + ctx()))  # execve is not selected

    def test_malformed_input(self):
        for data in [b'\x12\xff', b'\x12\x05x', b'\x00', b'\x0b']:
            with self.subTest(data=data), self.assertRaises(ValueError):
                list(fields(data))
        with self.assertRaises(ValueError):
            varint(b'\xff' * 10, 0)
        with self.assertRaises(ValueError):
            decode(struct.pack('<HHI', 20, 10, 0))


class EvidenceTests(unittest.TestCase):
    def cases(self, run):
        summary = summarize(*load(run), node=NODE)
        self.assertEqual(summary, json.loads((run / 'summary.json').read_text()))
        return {c['case']: c for c in summary['cases']}

    def test_retained_runs_support_the_report(self):
        self.assertEqual(len(RUNS), 3)
        for run in RUNS:
            with self.subTest(run=run.name):
                c = self.cases(run)
                errno = lambda case: [e['errno'] for e in c[case]['connect_exit']]
                # A successful TCP connect is an established, delivered connection.
                for case in ('tcp_established', 'concurrent_a', 'concurrent_b'):
                    self.assertEqual(errno(case), [0])
                    self.assertIn('UPDATE tcp ESTABLISHED assured', c[case]['conntrack_events'])
                    self.assertEqual(c[case]['delivered'], [{'proto': 'tcp', 'bytes': 1}])
                # Failed attempts still put packets on the wire.
                self.assertEqual(errno('tcp_refused'), [111])
                self.assertEqual(errno('tcp_blackhole'), [115])
                self.assertEqual(errno('tcp_policy_denied'), [115])
                for case in ('tcp_refused', 'tcp_blackhole', 'tcp_policy_denied'):
                    self.assertGreaterEqual(c[case]['tcp_syn_from_pod'], 1)
                    self.assertEqual(c[case]['delivered'], [])
                self.assertGreater(c['tcp_blackhole']['uplink_packets_to_blackhole'], 0)
                # A UDP connect sends nothing.
                self.assertEqual(errno('udp_connect_only'), [0])
                self.assertEqual(c['udp_connect_only']['packets_from_pod'], 0)
                # Egress without any connect record.
                for case in ('udp_sendto', 'dns_lookup', 'after_disconnect'):
                    self.assertEqual(c[case]['connect_exit'], [])
                    self.assertGreater(c[case]['packets_from_pod'], 0)
                self.assertTrue(c['after_disconnect']['receiver_disconnected'])
                self.assertEqual(c['udp_sendto']['delivered'], [{'proto': 'udp', 'bytes': 1}])

    def test_extra_fields_and_missing_cases_fail(self):
        rows, events, packets, flows, delivery, counters = load(RUNS[0])
        with self.assertRaises(ValueError):
            summarize(rows[:-1], events, packets, flows, delivery, counters, node=NODE)
        bad = copy.deepcopy(events)
        bad[0]['process_name'] = CANARY
        with self.assertRaises(ValueError):
            summarize(rows, bad, packets, flows, delivery, counters, node=NODE)

    def test_evidence_has_no_private_markers(self):
        for path in EVIDENCE.rglob('*.json'):
            text = path.read_text()
            self.assertNotIn(CANARY, text, path)
            self.assertNotIn('kubernetes.default', text, path)


if __name__ == '__main__':
    unittest.main()
