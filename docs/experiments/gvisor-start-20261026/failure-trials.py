"""Recorded experiment fixture; run only in the dedicated disposable VM.

Requires the setup documented in README.md. Not a production collector.
"""
import json, time
from trial import OUT, create, cleanup, task_start, probe_start, probe_stop, now, ctr, evidence, wait_stopped
records = []
id = 'gvisor-no-receiver-check'
info = create(id)
try:
    record = {'scenario': 'receiver_absent', 'inventory': [info], 'start': task_start(id)}
finally:
    cleanup(id)
records.append(record)
print('absent receiver', record, flush=True)
ids = ['gvisor-restart-existing', 'gvisor-restart-new']
record = {'scenario': 'receiver_restart', 'inventory': [create(ids[0], seconds=40), create(ids[1], seconds=2)]}
p = probe_start('restart-before', [ids[0]])
try:
    record['first_start'] = task_start(ids[0])
    assert record['first_start']['exit'] == 0
    time.sleep(0.2)
finally:
    probe_stop(p)
record['after_disconnect'] = {'observed_at': now(), 'tasks': ctr('tasks', 'list').stdout}
assert ids[0] in record['after_disconnect']['tasks'] and 'RUNNING' in record['after_disconnect']['tasks']
record['before'] = evidence('restart-before', [ids[0]])
p = probe_start('restart-after', ids)
try:
    time.sleep(1)
    record['replayed_records_before_new_start'] = len((OUT / 'restart-after.jsonl').read_text().splitlines())
    record['second_start'] = task_start(ids[1])
    assert record['second_start']['exit'] == 0
    wait_stopped([ids[1]])
finally:
    probe_stop(p)
    for id in reversed(ids):
        cleanup(id)
record['after'] = evidence('restart-after', [ids[1]])
records.append(record)
(OUT / 'failure-results.json').write_text(json.dumps(records, indent=2) + '\n')
print('receiver restart', record, flush=True)
