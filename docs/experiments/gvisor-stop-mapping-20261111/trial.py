#!/usr/bin/env python3
"""Disposable Linux/K3s research receiver for the gVisor stop-mapping trial.

This is not a node-agent event source. It accepts only container/start,
sentry/task_exit and sentry/exit_notify_parent, keeps fixed numeric context,
claimed IDs and exit status, and discards everything else (argv, cwd, env,
credentials, process names). Raw receive buffers are cleared after parsing.

Wire schema: google/gvisor release-20261019.0 common.proto and sentry.proto.
"""
import argparse
import json
import os
import pathlib
import socket
import struct
import subprocess
import threading
import time

LIMIT = 1 << 20
MAX_EVENTS = 4096
MAX_CLIENTS = 32
CANARY = 'GVS_STOPMAP_CANARY_2026'
IMAGE = 'docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662'
NS = 'gvisor-stopmap-20261111'
K = ['k3s', 'kubectl', '--request-timeout=15s']
KINDS = {1: 'container_start_claim', 4: 'exit_notify_parent', 5: 'task_exit'}
CONTEXT = {1: 'source_time_ns', 2: 'thread_id', 3: 'thread_start_time_ns',
           4: 'thread_group_id', 5: 'thread_group_start_time_ns'}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def varint(data, pos):
    value = 0
    for index in range(10):
        require(pos < len(data), 'truncated protobuf')
        byte = data[pos]
        pos += 1
        require(index != 9 or byte < 2, 'overflowing protobuf')
        value |= (byte & 127) << (7 * index)
        if not byte & 128:
            return value, pos
    raise ValueError('invalid protobuf')


def fields(data):
    require(len(data) <= LIMIT, 'oversized protobuf')
    pos = 0
    while pos < len(data):
        tag, pos = varint(data, pos)
        number, kind = tag >> 3, tag & 7
        require(number > 0, 'invalid protobuf tag')
        if kind == 0:
            value, pos = varint(data, pos)
        elif kind == 2:
            size, pos = varint(data, pos)
            require(size <= len(data) - pos, 'truncated protobuf field')
            value = data[pos:pos + size]
            pos += size
        elif kind in (1, 5):
            size = 8 if kind == 1 else 4
            require(size <= len(data) - pos, 'truncated fixed field')
            value = data[pos:pos + size]
            pos += size
        else:
            raise ValueError('unsupported protobuf wire kind')
        yield number, kind, value


def signed32(value):
    """Decode a protobuf int32 varint, which is sign-extended to 64 bits."""
    value &= (1 << 64) - 1
    return value - (1 << 64) if value >= 1 << 63 else value


def identity(data):
    value = bytes(data).decode('ascii')
    require(len(value) == 64 and all(c in '0123456789abcdef' for c in value), 'invalid claimed ID')
    return value


def decode(frame, connection=0):
    require(8 <= len(frame) <= LIMIT, 'invalid frame length')
    header, kind, drops = struct.unpack_from('<HHI', frame)
    require(8 <= header <= len(frame), 'invalid header')
    if kind not in KINDS:
        return None
    row = {'kind': KINDS[kind], 'message_type': kind, 'connection': connection,
           'sender_cumulative_drops': drops}
    if kind in (4, 5):
        row['wait_status'] = 0  # protobuf's omitted scalar default
    for number, wire, value in fields(frame[header:]):
        if number == 1 and wire == 2:
            for n, w, v in fields(value):
                if n == 6 and w == 2:
                    row['context_container_id'] = identity(v)
                elif n in CONTEXT and w == 0:
                    row[CONTEXT[n]] = v
        elif number == 2 and kind == 1 and wire == 2:
            row['container_id'] = identity(value)
        elif number == 2 and kind in (4, 5) and wire == 0:
            row['wait_status'] = signed32(value)
    row['observed_ns'] = time.time_ns()
    return row


class Receiver:
    """One listener at a fixed path; restart() replaces it to model a collector restart."""

    def __init__(self, path):
        self.path = path
        self.events = []
        self.lock = threading.Lock()
        self.errors = 0
        self.dropped = 0
        self.rejected_clients = 0
        self.connections = 0
        self.generation = 0
        parent = pathlib.Path(path).parent
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        st = parent.stat()
        require(st.st_uid == os.geteuid() and st.st_mode & 0o77 == 0, 'private receiver directory required')
        require(not pathlib.Path(path).exists(), 'socket already exists')
        self._open()

    def _open(self):
        self.closed = threading.Event()
        self.clients = []
        self.workers = []
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.listener.bind(self.path)
        os.chmod(self.path, 0o600)
        self.listener.listen(8)
        self.listener.settimeout(.2)
        self.worker = threading.Thread(target=self.accept)
        self.worker.start()

    def record(self, row):
        with self.lock:
            if len(self.events) < MAX_EVENTS:
                self.events.append(row)
            else:
                self.dropped += 1

    def accept(self):
        while not self.closed.is_set():
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self.lock:
                if len(self.clients) >= MAX_CLIENTS:
                    self.rejected_clients += 1
                    client.close()
                    continue
                self.clients.append(client)
                self.connections += 1
                connection = self.connections
            t = threading.Thread(target=self.receive, args=(client, connection))
            self.workers.append(t)
            t.start()

    def receive(self, client, connection):
        client.settimeout(2)
        buffer = bytearray(LIMIT + 1)
        try:
            require(client.recv(32) == b'\x08\x01', 'unsupported handshake')
            client.sendall(b'\x08\x01')
            client.settimeout(.2)
            self.record({'kind': 'source_connected', 'connection': connection,
                         'receiver_generation': self.generation, 'observed_ns': time.time_ns()})
            while not self.closed.is_set():
                try:
                    n, _, flags, _ = client.recvmsg_into([buffer])
                except socket.timeout:
                    continue
                if not n:
                    break
                try:
                    require(not flags & socket.MSG_TRUNC and n <= LIMIT, 'oversized packet')
                    event = decode(memoryview(buffer)[:n], connection)
                    if event:
                        self.record(event)
                finally:
                    buffer[:n] = b'\0' * n
        except (OSError, ValueError, UnicodeError):
            with self.lock:
                self.errors += 1
        finally:
            buffer[:] = b'\0' * len(buffer)
            client.close()
            self.record({'kind': 'source_disconnected', 'connection': connection,
                         'observed_ns': time.time_ns()})

    def _shutdown(self):
        self.closed.set()
        with self.lock:
            clients = list(self.clients)
        for client in clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.listener.close()
        self.worker.join(3)
        for worker in self.workers:
            worker.join(3)
        require(not self.worker.is_alive() and not any(t.is_alive() for t in self.workers),
                'receiver shutdown timed out')
        pathlib.Path(self.path).unlink(missing_ok=True)

    def restart(self):
        """Close every connection and the listener, then listen again at the same path."""
        self._shutdown()
        self.generation += 1
        self.record({'kind': 'receiver_restarted', 'receiver_generation': self.generation,
                     'observed_ns': time.time_ns()})
        self._open()

    def close(self):
        self._shutdown()


def run(args, payload=None, timeout=25):
    r = subprocess.run(args, input=json.dumps(payload) if payload else None,
                       capture_output=True, text=True, timeout=timeout)
    require(r.returncode == 0, 'runtime query failed (raw response suppressed)')
    return r.stdout


def query(args, payload=None):
    return json.loads(run(args, payload))


def container(name, command):
    return {'name': name, 'image': IMAGE, 'command': ['/bin/sh', '-c', command, CANARY],
            'workingDir': '/' + CANARY, 'volumeMounts': [{'name': 'cwd', 'mountPath': '/' + CANARY}],
            'resources': {'limits': {'cpu': '250m', 'memory': '128Mi'}}}


def pod(name, containers, restart='Never'):
    return {'apiVersion': 'v1', 'kind': 'Pod',
            'metadata': {'name': name, 'namespace': NS, 'labels': {'experiment': NS}},
            'spec': {'runtimeClassName': 'gvisor', 'restartPolicy': restart,
                     'terminationGracePeriodSeconds': 2,
                     'containers': [container(n, c) for n, c in containers],
                     'volumes': [{'name': 'cwd', 'emptyDir': {}}]}}


def create(obj):
    query(K + ['create', '-f', '-', '-o', 'json'], obj)
    return obj['metadata']['name']


def pod_state(name):
    return query(K + ['get', 'pod', name, '-n', NS, '-o', 'json'])


def container_ids(name, count, timeout=90):
    """Wait until every container of the Pod has a CRI ID; return {container name: ID}."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        state = pod_state(name)
        statuses = state.get('status', {}).get('containerStatuses', [])
        ids = {s['name']: s['containerID'].split('://', 1)[1] for s in statuses if s.get('containerID')}
        if len(ids) == count:
            return ids, state
        time.sleep(.1)
    raise ValueError('container IDs did not appear')


def inspect(cid):
    return query(['k3s', 'crictl', 'inspect', cid])['status']


def wait_exit(cids, timeout=90):
    """Poll CRI until every container has exited, keeping RUNNING sample times."""
    samples = {cid: [] for cid in cids}
    final = {}
    end = time.monotonic() + timeout
    while time.monotonic() < end and len(final) < len(cids):
        for cid in cids:
            if cid in final:
                continue
            status = inspect(cid)
            if status['state'] == 'CONTAINER_EXITED':
                final[cid] = status
            elif status['state'] == 'CONTAINER_RUNNING':
                samples[cid].append(time.time_ns())
        time.sleep(.1)
    require(len(final) == len(cids), 'container did not exit')
    return final, samples


def wait_running(cid, timeout=60):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if inspect(cid)['state'] == 'CONTAINER_RUNNING':
            return
        time.sleep(.1)
    raise ValueError('container did not reach RUNNING')


def ledger_row(case, pod_name, role, cid, state, status, samples, expected, **extra):
    info = query(['k3s', 'crictl', 'ps', '-a', '--id', cid, '-o', 'json'])['containers']
    require(len(info) == 1 and info[0]['id'] == cid, 'CRI identity mismatch')
    if expected is not None:
        require(status['exitCode'] == expected, 'unexpected runtime exit code')
    row = {'case': case, 'pod': pod_name, 'role': role, 'container_id': cid,
           'sandbox_id': info[0]['podSandboxId'], 'pod_uid': state['metadata']['uid'],
           'runtime_state': status['state'], 'exit_code': status['exitCode'],
           'expected_exit_code': expected, 'started_at': status['startedAt'],
           'finished_at': status['finishedAt'], 'running_samples_ns': samples}
    row.update(extra)
    return row


def single(case, command, expected, action=None, **extra):
    name = create(pod('stopmap-' + case.replace('_', '-'), [('workload', command)]))
    ids, state = container_ids(name, 1)
    cid = ids['workload']
    marks = {}
    if action:
        wait_running(cid)
        marks = action(cid, state) or {}
    final, samples = wait_exit([cid])
    extra.update(marks)
    return [ledger_row(case, name, 'workload', cid, state, final[cid], samples[cid], expected, **extra)]


def crictl_stop(timeout):
    def act(cid, _):
        run(['k3s', 'crictl', 'stop', '--timeout', str(timeout), cid], timeout=timeout + 20)
    return act


def ctr_kill(cid, _):
    r = subprocess.run(['k3s', 'ctr', '-n', 'k8s.io', 'tasks', 'kill', '--signal', 'SIGKILL', cid],
                       capture_output=True, timeout=15)
    require(r.returncode == 0, 'cannot terminate owned trial container')


def exec_then_kill(cid, state):
    name = state['metadata']['name']
    before = time.time_ns()
    r = subprocess.run(K + ['exec', '-n', NS, name, '-c', 'workload', '--', '/bin/sh', '-c',
                            'sleep 1; exit 4', CANARY], capture_output=True, timeout=30)
    require(r.returncode == 4, 'exec session did not report its own exit code')
    after = time.time_ns()
    time.sleep(1)
    running = inspect(cid)['state'] == 'CONTAINER_RUNNING'
    require(running, 'exec control did not leave a running container')
    ctr_kill(cid, state)
    return {'exec_started_ns': before, 'exec_finished_ns': after, 'running_after_exec_exit': running}


def sentry_kill(cid, state):
    """SIGKILL only the runsc-sandbox (Sentry) host process owning this trial sandbox."""
    sandbox = query(['k3s', 'crictl', 'ps', '-a', '--id', cid, '-o', 'json'])['containers'][0]['podSandboxId']
    owners = []
    for proc in pathlib.Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            args = (proc / 'cmdline').read_bytes().split(b'\0')
        except OSError:
            continue
        if args and args[0].endswith(b'runsc-sandbox') and sandbox.encode() in args:
            owners.append(int(proc.name))
    require(len(owners) == 1, 'could not identify one owned Sentry process')
    killed = time.time_ns()
    os.kill(owners[0], 9)
    return {'sentry_killed_ns': killed}


def multi_container():
    name = create(pod('stopmap-multi', [('first', 'sleep 2; exit 11'), ('second', 'sleep 6; exit 12')]))
    ids, state = container_ids(name, 2)
    final, samples = wait_exit(list(ids.values()))
    return [ledger_row('multi_container', name, role, cid, state, final[cid], samples[cid],
                       11 if role == 'first' else 12) for role, cid in ids.items()]


def concurrent():
    names = [create(pod('stopmap-concurrent-%d' % i, [('workload', 'sleep 3; exit %d' % (20 + i))]))
             for i in range(1, 5)]
    found = [(n,) + container_ids(n, 1) for n in names]
    cids = [ids['workload'] for _, ids, _ in found]
    final, samples = wait_exit(cids)
    return [ledger_row('concurrent', n, 'workload', ids['workload'], state, final[ids['workload']],
                       samples[ids['workload']], 20 + i) for i, (n, ids, state) in enumerate(found, 1)]


def restart_in_sandbox():
    """Same sandbox, two container instances: claimed thread groups may be reused."""
    name = create(pod('stopmap-restart', [('workload', 'sleep 2; exit 13')], restart='OnFailure'))
    end = time.monotonic() + 120
    first = None
    while time.monotonic() < end:
        state = pod_state(name)
        status = state['status'].get('containerStatuses', [{}])[0]
        last = status.get('lastState', {}).get('terminated', {})
        if first is None and last.get('containerID'):
            first = last['containerID'].split('://', 1)[1]
            first_status = inspect(first)
        current = status.get('containerID', '').split('://', 1)[-1]
        if first and current and current != first:
            second = current
            break
        time.sleep(.1)
    require(first is not None, 'container was not restarted')
    final, samples = wait_exit([second])
    rows = [ledger_row('restart_in_sandbox', name, 'first_instance', first, state, first_status, [], 13),
            ledger_row('restart_in_sandbox', name, 'second_instance', second, state, final[second],
                       samples[second], 13)]
    run(K + ['delete', 'pod', name, '-n', NS, '--grace-period=0', '--wait=false'])
    return rows


def receiver_restart(receiver):
    """A sandbox connected before the restart, then one created after it."""
    before = create(pod('stopmap-before-restart', [('workload', 'sleep 10; exit 17')]))
    ids_before, state_before = container_ids(before, 1)
    wait_running(ids_before['workload'])
    time.sleep(1)
    receiver.restart()
    restarted = time.time_ns()
    after = create(pod('stopmap-after-restart', [('workload', 'sleep 3; exit 18')]))
    ids_after, state_after = container_ids(after, 1)
    cids = [ids_before['workload'], ids_after['workload']]
    final, samples = wait_exit(cids)
    return [ledger_row('receiver_restart', before, 'connected_before_restart', cids[0], state_before,
                       final[cids[0]], samples[cids[0]], 17, receiver_restarted_ns=restarted),
            ledger_row('receiver_restart', after, 'created_after_restart', cids[1], state_after,
                       final[cids[1]], samples[cids[1]], 18, receiver_restarted_ns=restarted)]


def main():
    global NS
    p = argparse.ArgumentParser()
    p.add_argument('--namespace', default=NS)
    p.add_argument('--output', required=True)
    p.add_argument('--socket', default='/run/kubescape/gvisor-stopmap/events.sock')
    args = p.parse_args()
    require(args.namespace.startswith('gvisor-stopmap-') and
            all(c in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in args.namespace), 'dedicated namespace required')
    NS = args.namespace
    out = pathlib.Path(args.output)
    out.mkdir(mode=0o700, exist_ok=False)
    query(K + ['create', 'namespace', NS, '-o', 'json'])
    receiver = Receiver(args.socket)
    rows = []
    plan = [
        lambda: single('normal_exit', 'sleep 1; (sleep 1); wait; sleep 2; exit 7', 7),
        lambda: single('short_lived', 'exit 5', 5),
        lambda: single('graceful_stop', 'trap "exit 3" TERM; sleep 600 & wait', 3, crictl_stop(10)),
        # Default TERM disposition: the shell is killed by SIGTERM inside gVisor (143).
        lambda: single('term_default', 'sleep 600', 143, crictl_stop(10)),
        # TERM ignored: the runtime escalates to SIGKILL after the timeout (137).
        lambda: single('grace_timeout', 'trap "" TERM; sleep 600 & wait', 137, crictl_stop(2)),
        lambda: single('forced_kill', 'sleep 600', 137, ctr_kill),
        lambda: single('exec_session', 'sleep 600', 137, exec_then_kill),
        lambda: single('sentry_failure', 'sleep 600', None, sentry_kill),
        multi_container,
        concurrent,
        restart_in_sandbox,
        lambda: receiver_restart(receiver),
    ]
    try:
        for step in plan:
            rows.extend(step())
            (out / 'runtime-ledger.json').write_text(json.dumps(rows, indent=2) + '\n')
        time.sleep(1)
    finally:
        receiver.close()
    events = receiver.events
    require(CANARY not in json.dumps(events), 'sensitive marker retained')
    (out / 'events.json').write_text(json.dumps(events, indent=2) + '\n')
    (out / 'receiver.json').write_text(json.dumps({
        'decode_or_transport_errors': receiver.errors, 'local_queue_drops': receiver.dropped,
        'rejected_clients': receiver.rejected_clients, 'connections': receiver.connections,
        'receiver_restarts': receiver.generation, 'production_stop_events_emitted': 0}, indent=2) + '\n')
    print(json.dumps({'containers': len(rows), 'events': len(events), 'production_stop_events_emitted': 0}))


if __name__ == '__main__':
    main()
