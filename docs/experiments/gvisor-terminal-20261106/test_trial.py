import struct
import unittest
from trial import CANARY, decode, fields, varint


def number(value):
    out=bytearray()
    while value>=128:out.append((value&127)|128);value>>=7
    out.append(value);return bytes(out)


def blob(field,value):return number(field*8+2)+number(len(value))+value


class DecodeTests(unittest.TestCase):
    def test_exit_status_and_minimal_context(self):
        context=number(2*8)+number(17)+number(4*8)+number(17)+blob(6,b'a'*64)
        frame=struct.pack('<HHI',8,5,0)+blob(1,context)+number(2*8)+number(7<<8)
        row=decode(frame)
        self.assertEqual((row['kind'],row['thread_id'],row['wait_status']),('task_exit',17,1792))
        self.assertEqual(row['context_container_id'],'a'*64)

    def test_start_discards_sensitive_unknown_fields(self):
        payload=blob(2,b'b'*64)+blob(3,CANARY.encode())+blob(4,CANARY.encode())
        result=decode(struct.pack('<HHI',8,1,0)+payload)
        self.assertNotIn(CANARY,str(result))
        self.assertEqual(result['container_id'],'b'*64)

    def test_malformed_lengths_varints_and_ids(self):
        for data in [b'\x12\xff',b'\x12\x05x',b'\x00',b'\x0b']:
            with self.subTest(data=data),self.assertRaises(ValueError):list(fields(data))
        with self.assertRaises(ValueError):varint(b'\xff'*10,0)
        with self.assertRaises(ValueError):decode(struct.pack('<HHI',8,5,0)+blob(1,blob(6,b'not-an-id')))
        with self.assertRaises(ValueError):decode(struct.pack('<HHI',20,5,0))

    def test_other_points_are_not_misclassified(self):
        self.assertIsNone(decode(struct.pack('<HHI',8,10,0)))


class EvidenceTests(unittest.TestCase):
    def test_retained_matrix_and_nonterminal_controls(self):
        import json,pathlib
        from analyze import analyze
        root=pathlib.Path(__file__).parent/'evidence'
        result=analyze(json.loads((root/'runtime-ledger.json').read_text()),json.loads((root/'events.json').read_text()),json.loads((root/'receiver.json').read_text()))
        self.assertTrue(result['cases'][0]['cri_running_sample_after_child_exit'])
        self.assertTrue(result['cases'][2]['running_after_receiver_disconnect'])
        self.assertFalse(result['container_stop_contract_ready'])

    def test_extra_retained_fields_and_missing_cases_fail(self):
        import json,pathlib
        from analyze import analyze
        root=pathlib.Path(__file__).parent/'evidence'
        rows=json.loads((root/'runtime-ledger.json').read_text());events=json.loads((root/'events.json').read_text());counters=json.loads((root/'receiver.json').read_text())
        with self.assertRaises(ValueError):analyze(rows[:-1],events,counters)
        events[0]['argv']=CANARY
        with self.assertRaises(ValueError):analyze(rows,events,counters)


if __name__=='__main__':unittest.main()
