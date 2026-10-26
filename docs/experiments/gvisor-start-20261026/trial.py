"""Recorded experiment fixture; run only in the dedicated disposable VM.

Requires the setup documented in README.md. Not a production collector.
"""
from collections import Counter
import concurrent.futures, datetime, json, os, pathlib, shutil, signal, socket, subprocess, time
BASE = pathlib.Path('/home/ubuntu/gvisor-trial')
OUT = BASE / 'evidence'
CANARY = 'GVS_TRIAL_CANARY_2026'
ROOT = '/opt/gvisor-trial/rootfs'
NS = 'gvisor-trial'
SOCKET = '/run/kubescape/gvisor-events.sock'
results = []

def save():
    (OUT / 'results.json').write_text(json.dumps(results, indent=2) + '\n')

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def ctr(*args, check=True):
    r = subprocess.run(['ctr', '--namespace', NS, *args], capture_output=True, text=True, timeout=30)
    if check and r.returncode:
        raise RuntimeError(r.stderr.replace(CANARY, '[CANARY]'))
    return r

def create(id, runtime='io.containerd.runsc.v1', seconds=1, child=None):
    args = ['containers', 'create', '--rootfs', '--runtime', runtime]
    if runtime == 'io.containerd.runsc.v1':
        args += ['--runtime-config-path', str(BASE / 'runsc.toml')]
    if child:
        args += ['--annotation', 'io.kubernetes.cri.container-type=container', '--annotation', 'io.kubernetes.cri.sandbox-id=' + child]
    args += ['--cwd', '/' + CANARY, ROOT + '-child' if child else ROOT, id, '/bin/sh', '-c', 'sleep ' + str(seconds), CANARY]
    ctr(*args)
    info = json.loads(ctr('containers', 'info', id).stdout)
    assert info['ID'] == id and info['Runtime']['Name'] == runtime
    return {'id': info['ID'], 'runtime': info['Runtime']['Name'], 'inventory_checked_at': now()}

def cleanup(id):
    ctr('tasks', 'kill', '--signal', 'SIGKILL', id, check=False)
    ctr('tasks', 'delete', id, check=False)
    ctr('containers', 'delete', id, check=False)

def probe_start(name, ids):
    stdout = (OUT / (name + '.jsonl')).open('w')
    stderr = (OUT / (name + '.stderr')).open('w')
    args = ['gvisor-start-probe', '--socket', SOCKET]
    for id in ids:
        args += ['--container-id', id]
    p = subprocess.Popen(args, stdout=stdout, stderr=stderr)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as s:
                s.settimeout(0.2)
                s.connect(SOCKET)
                s.sendall(b'\x08\x01')
                if s.recv(32) == b'\x08\x01':
                    return (p, stdout, stderr)
        except OSError:
            time.sleep(0.05)
    p.kill()
    p.wait()
    raise RuntimeError('probe readiness failed')

def probe_stop(probe):
    (p, stdout, stderr) = probe
    p.send_signal(signal.SIGTERM)
    p.wait(timeout=5)
    stdout.close()
    stderr.close()
    assert p.returncode == 0 and (not pathlib.Path(SOCKET).exists())

def task_start(id):
    start = time.monotonic()
    before = now()
    r = ctr('tasks', 'start', '--detach', id, check=False)
    return {'id': id, 'start_requested_at': before, 'start_returned_at': now(), 'start_latency_ms': round((time.monotonic() - start) * 1000, 3), 'exit': r.returncode, 'error': r.stderr.replace(CANARY, '[CANARY]')}

def wait_stopped(ids):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        lines = ctr('tasks', 'list').stdout.splitlines()[1:]
        states = {p[0]: p[2] for line in lines if len((p := line.split())) >= 3}
        if all((states.get(id) == 'STOPPED' for id in ids)):
            return {'observed_at': now(), 'states': {id: states[id] for id in ids}}
        time.sleep(0.1)
    raise RuntimeError('tasks did not stop')

def evidence(name, ids):
    expected = {id: 1 for id in ids}
    (OUT / (name + '-expected.json')).write_text(json.dumps(expected, indent=2) + '\n')
    events = [json.loads(line) for line in (OUT / (name + '.jsonl')).read_text().splitlines()]
    counts = Counter((e['ContainerID'] for e in events))
    matches = counts == Counter(expected)
    assert all((e['Dropped'] == 0 and e['Source'] == 'gvisor_trace' for e in events))
    for path in [OUT / (name + '.jsonl'), OUT / (name + '.stderr')]:
        assert CANARY not in path.read_text()
    return {'counts_match': matches, 'received': len(events), 'expected': len(ids), 'missing': sorted(set(ids) - set(counts)), 'sender_dropped': max([e['Dropped'] for e in events], default=0), 'canary_absent': True}

def main():
    OUT.mkdir(mode=448, exist_ok=False)
    pathlib.Path(ROOT + '/' + CANARY).mkdir(exist_ok=True)
    shutil.copytree(ROOT, ROOT + '-child', ignore=shutil.ignore_patterns('.gvisor*'), dirs_exist_ok=True)
    ids = ['gvisor-repeat-%02d' % i for i in range(1, 21)]
    record = {'scenario': 'twenty_repeated', 'inventory': [create(id) for id in ids], 'starts': []}
    results.append(record)
    save()
    p = probe_start('repeated', ids)
    try:
        for id in ids:
            r = task_start(id)
            record['starts'].append(r)
            save()
            assert r['exit'] == 0
            wait_stopped([id])
            cleanup(id)
        time.sleep(0.2)
    finally:
        probe_stop(p)
    record['evidence'] = evidence('repeated', ids)
    save()
    print('repeated', record['evidence'], flush=True)
    ids = ['gvisor-concurrent-a', 'gvisor-concurrent-b']
    record = {'scenario': 'two_concurrent', 'inventory': [create(id, seconds=5) for id in ids]}
    results.append(record)
    save()
    p = probe_start('concurrent', ids)
    try:
        with concurrent.futures.ThreadPoolExecutor(2) as workers:
            record['starts'] = list(workers.map(task_start, ids))
        assert all((r['exit'] == 0 for r in record['starts']))
        record['overlap'] = {'observed_at': now(), 'tasks': ctr('tasks', 'list').stdout}
        assert all((id in record['overlap']['tasks'] for id in ids))
        assert record['overlap']['tasks'].count('RUNNING') == 2
        record['stopped'] = wait_stopped(ids)
    finally:
        probe_stop(p)
        for id in ids:
            cleanup(id)
    record['evidence'] = evidence('concurrent', ids)
    save()
    print('concurrent', record['evidence'], flush=True)
    ids = ['gvisor-root', 'gvisor-child']
    record = {'scenario': 'root_and_child', 'inventory': [create(ids[0], seconds=10), create(ids[1], seconds=2, child=ids[0])]}
    results.append(record)
    save()
    p = probe_start('root-child', ids)
    try:
        record['starts'] = [task_start(ids[0]), task_start(ids[1])]
        assert all((r['exit'] == 0 for r in record['starts']))
        record['overlap'] = {'observed_at': now(), 'tasks': ctr('tasks', 'list').stdout}
        wait_stopped([ids[1]])
    finally:
        probe_stop(p)
        for id in reversed(ids):
            cleanup(id)
    record['evidence'] = evidence('root-child', ids)
    save()
    print('root-child', record['evidence'], flush=True)
    id = 'gvisor-no-receiver'
    info = create(id)
    try:
        record = {'scenario': 'receiver_absent', 'inventory': [info], 'start': task_start(id)}
    finally:
        cleanup(id)
    results.append(record)
    save()
    (OUT / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    print('receiver absent', record['start'], flush=True)
if __name__ == '__main__':
    main()
