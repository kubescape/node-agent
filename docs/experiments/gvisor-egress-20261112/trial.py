#!/usr/bin/env python3
"""Disposable research receiver for the gVisor egress-visibility trial.

This is not a node-agent event source. It accepts only container/start,
syscall/connect and the raw sendto/sendmsg points. It keeps numeric context,
claimed IDs, connect results and the destination family/address/port of
AF_INET and AF_INET6 sockaddrs. It discards argv, cwd, env, credentials,
process names, fd paths and AF_UNIX paths, and clears raw buffers.

Ground truth is collected on the host at three more levels: packets on the
pod bridge and the uplink (tcpdump), host conntrack events, and what a host
listener actually accepted or received.

Wire schema: google/gvisor release-20261019.0 common.proto and syscall.proto.
"""
import argparse
import ipaddress
import json
import os
import pathlib
import socket
import struct
import subprocess
import threading
import time

LIMIT = 1 << 20
MAX_EVENTS = 8192
CANARY = 'GVS_EGRESS_CANARY_2026'
IMAGE = 'docker.io/library/python@sha256:9ef1a599f863231c3d91e941389bfdc4a2d6070557243d54df1a4e57015b960e'
NS = 'gvisor-egress-20261112'
K = ['k3s', 'kubectl', '--request-timeout=15s']
TCP_OPEN, UDP_PORT, TCP_CLOSED, BLACKHOLE_PORT = 18080, 18081, 18082, 18083
BLACKHOLE = '192.0.2.10'  # TEST-NET-1: routed off the node, never answered
RAW_SEND = {206: 'sendto', 211: 'sendmsg'}  # arm64 syscall numbers
CONTEXT = {1: 'source_time_ns', 2: 'thread_id', 4: 'thread_group_id'}

# The workload. The case name is argv[1]; the destination host is argv[2].
WORKLOAD = r'''
import socket, sys, time
case, node = sys.argv[1], sys.argv[2]
time.sleep(float(sys.argv[3]))
def tcp(host, port, blocking=True, wait=0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setblocking(blocking)
    try:
        s.connect((host, port))
        if blocking:
            s.sendall(b"x")
    except (BlockingIOError, ConnectionRefusedError, OSError):
        pass
    time.sleep(wait)
    s.close()
def udp(connect, send):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if connect:
        s.connect((node, 18081))
        if send:
            s.send(b"x")
    elif send:
        s.sendto(b"x", (node, 18081))
    time.sleep(1)
    s.close()
if case in ("tcp_established", "concurrent_a", "concurrent_b", "after_disconnect"):
    tcp(node, 18080)
elif case == "tcp_refused":
    tcp(node, 18082)
elif case == "tcp_blackhole":
    tcp("192.0.2.10", 18083, blocking=False, wait=4)
elif case == "tcp_policy_denied":
    tcp(node, 18080, blocking=False, wait=4)
elif case == "udp_connect_only":
    udp(True, False)
elif case == "udp_sendto":
    udp(False, True)
elif case == "udp_connect_send":
    udp(True, True)
elif case == "dns_lookup":
    try:
        socket.getaddrinfo("kubernetes.default.svc.cluster.local", 443)
    except OSError:
        pass
time.sleep(1)
'''


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


def signed64(value):
    return value - (1 << 64) if value >= 1 << 63 else value


def identity(data):
    value = bytes(data).decode('ascii')
    require(len(value) == 64 and all(c in '0123456789abcdef' for c in value), 'invalid claimed ID')
    return value


def sockaddr(data):
    """Keep only family, address and port. AF_UNIX paths are never retained."""
    data = bytes(data)
    require(len(data) <= 128, 'oversized sockaddr')
    if len(data) < 2:
        return {'family': 'invalid'}
    family = struct.unpack_from('<H', data)[0]
    if family == socket.AF_INET and len(data) >= 8:
        return {'family': 'inet', 'port': struct.unpack_from('>H', data, 2)[0],
                'address': str(ipaddress.IPv4Address(data[4:8]))}
    if family == socket.AF_INET6 and len(data) >= 24:
        return {'family': 'inet6', 'port': struct.unpack_from('>H', data, 2)[0],
                'address': str(ipaddress.IPv6Address(data[8:24]))}
    if family == socket.AF_UNIX:
        return {'family': 'unix'}
    if family == socket.AF_UNSPEC:
        return {'family': 'unspec'}
    return {'family': 'other'}


def context(value, row):
    for n, w, v in fields(value):
        if n == 6 and w == 2:
            row['context_container_id'] = identity(v)
        elif n in CONTEXT and w == 0:
            row[CONTEXT[n]] = v


def exit_fields(value, row):
    row['phase'] = 'exit'
    row['result'] = 0
    row['errno'] = 0
    for n, w, v in fields(value):
        if n == 1 and w == 0:
            row['result'] = signed64(v)
        elif n == 2 and w == 0:
            row['errno'] = signed64(v)


def decode(frame, connection=0):
    require(8 <= len(frame) <= LIMIT, 'invalid frame length')
    header, kind, drops = struct.unpack_from('<HHI', frame)
    require(8 <= header <= len(frame), 'invalid header')
    if kind not in (1, 6, 10):
        return None
    row = {'message_type': kind, 'connection': connection, 'sender_cumulative_drops': drops}
    payload = frame[header:]
    if kind == 1:
        row['kind'] = 'container_start_claim'
        for number, wire, value in fields(payload):
            if number == 1 and wire == 2:
                context(value, row)
            elif number == 2 and wire == 2:
                row['container_id'] = identity(value)
    elif kind == 10:
        row['kind'] = 'connect'
        row['phase'] = 'enter'
        for number, wire, value in fields(payload):
            if number == 1 and wire == 2:
                context(value, row)
            elif number == 2 and wire == 2:
                exit_fields(value, row)
            elif number == 4 and wire == 0:
                row['fd'] = signed64(value)
            elif number == 6 and wire == 2:
                row['destination'] = sockaddr(value)
    else:
        sysno = None
        parsed = {}
        for number, wire, value in fields(payload):
            if number == 1 and wire == 2:
                context(value, parsed)
            elif number == 2 and wire == 2:
                exit_fields(value, parsed)
            elif number == 4 and wire == 0:
                sysno = value
        if sysno not in RAW_SEND:
            return None
        row['kind'] = RAW_SEND[sysno]
        row.setdefault('phase', 'enter')
        row.update(parsed)
    row['observed_ns'] = time.time_ns()
    return row


class Receiver:
    def __init__(self, path):
        self.path = path
        self.events = []
        self.lock = threading.Lock()
        self.errors = 0
        self.dropped = 0
        self.connections = 0
        self.rejected = 0
        parent = pathlib.Path(path).parent
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        st = parent.stat()
        require(st.st_uid == os.geteuid() and st.st_mode & 0o77 == 0, 'private receiver directory required')
        require(not pathlib.Path(path).exists(), 'socket already exists')
        self.closed = threading.Event()
        self.clients = []
        self.workers = []
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.listener.bind(path)
        os.chmod(path, 0o600)
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
                # self.clients holds only active connections; a rejected one is counted.
                if len(self.clients) >= 32:
                    self.rejected += 1
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
            with self.lock:
                if client in self.clients:
                    self.clients.remove(client)
            self.record({'kind': 'source_disconnected', 'connection': connection, 'observed_ns': time.time_ns()})

    def disconnect(self):
        with self.lock:
            clients = list(self.clients)
        for client in clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def close(self):
        self.closed.set()
        self.disconnect()
        self.listener.close()
        self.worker.join(3)
        for worker in self.workers:
            worker.join(3)
        require(not self.worker.is_alive() and not any(t.is_alive() for t in self.workers), 'receiver shutdown timed out')
        pathlib.Path(self.path).unlink(missing_ok=True)


class Listeners:
    """Delivery ground truth: what the destination actually accepted or received."""

    def __init__(self, address):
        self.records = []
        self.lock = threading.Lock()
        self.closed = threading.Event()
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind((address, TCP_OPEN))
        self.tcp.listen(16)
        self.tcp.settimeout(.2)
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind((address, UDP_PORT))
        self.udp.settimeout(.2)
        self.threads = [threading.Thread(target=self.serve_tcp), threading.Thread(target=self.serve_udp)]
        for t in self.threads:
            t.start()

    def add(self, row):
        with self.lock:
            self.records.append(row)

    def serve_tcp(self):
        while not self.closed.is_set():
            try:
                client, peer = self.tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            client.settimeout(2)
            try:
                received = len(client.recv(16))
            except OSError:
                received = 0
            client.close()
            self.add({'proto': 'tcp', 'peer': peer[0], 'peer_port': peer[1], 'bytes': received,
                      'host_ns': time.time_ns()})

    def serve_udp(self):
        while not self.closed.is_set():
            try:
                data, peer = self.udp.recvfrom(64)
            except socket.timeout:
                continue
            except OSError:
                break
            self.add({'proto': 'udp', 'peer': peer[0], 'peer_port': peer[1], 'bytes': len(data),
                      'host_ns': time.time_ns()})

    def close(self):
        self.closed.set()
        for t in self.threads:
            t.join(3)
        self.tcp.close()
        self.udp.close()


def trial_events(events, rows):
    """Keep only events from connections that belong to the trial's own sandboxes.

    A connection belongs to the trial when it carried a start claim for a
    container or sandbox ID in the ledger. Every kept event that has a context
    container ID must also name a ledger container or sandbox.
    """
    ids = {r['container_id'] for r in rows} | {r['sandbox_id'] for r in rows}
    connections = {e['connection'] for e in events
                   if e.get('kind') == 'container_start_claim' and e.get('container_id') in ids}
    kept = [e for e in events if e.get('connection') in connections
            and ('context_container_id' not in e or e['context_container_id'] in ids)]
    return kept, len(events) - len(kept)


def run(args, payload=None, timeout=25):
    r = subprocess.run(args, input=json.dumps(payload) if payload else None,
                       capture_output=True, text=True, timeout=timeout)
    require(r.returncode == 0, 'runtime query failed (raw response suppressed)')
    return r.stdout


def query(args, payload=None):
    return json.loads(run(args, payload))


def pod(case, node, delay, labels=None):
    return {'apiVersion': 'v1', 'kind': 'Pod',
            'metadata': {'name': 'egress-' + case.replace('_', '-'), 'namespace': NS,
                         'labels': dict({'experiment': NS, 'case': case.replace('_', '-')}, **(labels or {}))},
            'spec': {'runtimeClassName': 'gvisor', 'restartPolicy': 'Never',
                     'terminationGracePeriodSeconds': 2,
                     'containers': [{'name': 'workload', 'image': IMAGE,
                                     'command': ['python3', '-c', WORKLOAD, case, node, str(delay), CANARY],
                                     'resources': {'limits': {'cpu': '250m', 'memory': '128Mi'}}}]}}


def wait_pod(name, timeout=120):
    """Wait for the container ID and Pod IP, then for the container to exit."""
    end = time.monotonic() + timeout
    cid = ip = state = None
    while time.monotonic() < end:
        state = query(K + ['get', 'pod', name, '-n', NS, '-o', 'json'])
        statuses = state.get('status', {}).get('containerStatuses', [])
        if statuses and statuses[0].get('containerID'):
            cid = statuses[0]['containerID'].split('://', 1)[1]
        ip = state.get('status', {}).get('podIP')
        if cid and ip:
            break
        time.sleep(.1)
    require(cid and ip, 'container ID or Pod IP did not appear')
    return cid, ip, state


def finish(case, name, cid, ip, state, timeout=120, **extra):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        status = query(['k3s', 'crictl', 'inspect', cid])['status']
        if status['state'] == 'CONTAINER_EXITED':
            break
        time.sleep(.2)
    require(status['state'] == 'CONTAINER_EXITED' and status['exitCode'] == 0, 'workload did not exit cleanly')
    info = query(['k3s', 'crictl', 'ps', '-a', '--id', cid, '-o', 'json'])['containers']
    require(len(info) == 1 and info[0]['id'] == cid, 'CRI identity mismatch')
    row = {'case': case, 'pod': name, 'container_id': cid, 'sandbox_id': info[0]['podSandboxId'],
           'pod_uid': state['metadata']['uid'], 'pod_ip': ip, 'started_at': status['startedAt'],
           'finished_at': status['finishedAt'], 'exit_code': status['exitCode']}
    row.update(extra)
    return row


def single(case, node, delay=2, labels=None, during=None):
    name = run(K + ['create', '-f', '-', '-o', 'name'], pod(case, node, delay, labels)).strip().split('/')[-1]
    cid, ip, state = wait_pod(name)
    extra = during(cid) if during else {}
    return [finish(case, name, cid, ip, state, **(extra or {}))]


def concurrent(node):
    names = [run(K + ['create', '-f', '-', '-o', 'name'], pod(c, node, 4)).strip().split('/')[-1]
             for c in ('concurrent_a', 'concurrent_b')]
    found = [(c, n) + wait_pod(n) for c, n in zip(('concurrent_a', 'concurrent_b'), names)]
    return [finish(c, n, cid, ip, state) for c, n, cid, ip, state in found]


def deny_policy():
    return {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
            'metadata': {'name': 'deny-egress', 'namespace': NS},
            'spec': {'podSelector': {'matchLabels': {'egress': 'denied'}}, 'policyTypes': ['Egress'], 'egress': []}}


def capture(args, path):
    out = open(path, 'w')
    return subprocess.Popen(args, stdout=out, stderr=subprocess.DEVNULL, start_new_session=True), out


def main():
    global NS
    p = argparse.ArgumentParser()
    p.add_argument('--namespace', default=NS)
    p.add_argument('--output', required=True)
    p.add_argument('--private', required=True, help='root-only directory for raw captures (never exported)')
    p.add_argument('--node-ip', required=True)
    p.add_argument('--bridge', default='cni0')
    p.add_argument('--uplink', required=True)
    p.add_argument('--socket', default='/run/kubescape/gvisor-egress/events.sock')
    args = p.parse_args()
    require(args.namespace.startswith('gvisor-egress-') and
            all(c in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in args.namespace), 'dedicated namespace required')
    NS = args.namespace
    node = str(ipaddress.IPv4Address(args.node_ip))
    out = pathlib.Path(args.output)
    out.mkdir(mode=0o700, exist_ok=False)
    private = pathlib.Path(args.private)
    private.mkdir(mode=0o700, exist_ok=False)
    query(K + ['create', 'namespace', NS, '-o', 'json'])
    query(K + ['create', '-f', '-', '-o', 'json'], deny_policy())
    ports = 'portrange %d-%d' % (TCP_OPEN, BLACKHOLE_PORT)
    commands = {
        'bridge': ['tcpdump', '-i', args.bridge, '-nn', '-tt', '-l', '-s', '96',
                   'net 10.42.0.0/16 and (tcp %s or udp %s or port 53 or host %s or icmp)' % (ports, ports, BLACKHOLE)],
        'uplink': ['tcpdump', '-i', args.uplink, '-nn', '-tt', '-l', '-s', '96', 'host %s' % BLACKHOLE],
        'conntrack': ['conntrack', '-E', '-o', 'timestamp,id', '-s', '10.42.0.0/16'],
    }
    procs = {}
    listeners = receiver = None
    rows = []

    def captures_alive(when):
        for name, (proc, _) in procs.items():
            require(proc.poll() is None, '%s capture exited %s' % (name, when))

    def disconnect_then_wait(cid):
        # The workload connects about six seconds after it starts. Disconnect only
        # while it is running, and fail the case if it already exited.
        end = time.monotonic() + 60
        state = None
        while time.monotonic() < end:
            state = query(['k3s', 'crictl', 'inspect', cid])['status']['state']
            if state != 'CONTAINER_CREATED':
                break
            time.sleep(.1)
        require(state == 'CONTAINER_RUNNING', 'workload was not running before the disconnect')
        receiver.disconnect()
        disconnected = time.time_ns()
        require(query(['k3s', 'crictl', 'inspect', cid])['status']['state'] == 'CONTAINER_RUNNING',
                'workload exited before the disconnect took effect')
        return {'receiver_disconnected_ns': disconnected, 'running_at_disconnect': True}

    plan = [
        lambda: single('tcp_established', node),
        lambda: single('tcp_refused', node),
        lambda: single('tcp_blackhole', node),
        lambda: single('tcp_policy_denied', node, labels={'egress': 'denied'}),
        lambda: single('udp_connect_only', node),
        lambda: single('udp_sendto', node),
        lambda: single('udp_connect_send', node),
        lambda: single('dns_lookup', node),
        lambda: concurrent(node),
        lambda: single('after_disconnect', node, delay=6, during=disconnect_then_wait),
    ]
    try:
        listeners = Listeners(node)
        receiver = Receiver(args.socket)
        for name, command in commands.items():
            procs[name] = capture(command, private / (name + '.txt'))
        time.sleep(2)
        captures_alive('at startup')
        for step in plan:
            rows.extend(step())
            (out / 'runtime-ledger.json').write_text(json.dumps(rows, indent=2) + '\n')
        time.sleep(3)
        captures_alive('during the trial')
    finally:
        # Each cleanup step runs on its own, so one failure cannot leave a capture running.
        for close in ([receiver.close] if receiver else []) + ([listeners.close] if listeners else []):
            try:
                close()
            except Exception:
                pass
        for proc, handle in procs.values():
            try:
                proc.terminate()
                proc.wait(5)
            except Exception:
                proc.kill()
            finally:
                handle.close()
    for name in commands:
        require((private / (name + '.txt')).stat().st_size > 0, '%s capture recorded nothing' % name)
    events, excluded = trial_events(receiver.events, rows)
    require(CANARY not in json.dumps(events), 'sensitive marker retained')
    rows_json = lambda rows: '[\n' + ',\n'.join(json.dumps(r, sort_keys=True) for r in rows) + '\n]\n'
    (out / 'events.json').write_text(rows_json(events))
    (out / 'delivery.json').write_text(rows_json(listeners.records))
    (out / 'receiver.json').write_text(json.dumps({
        'decode_or_transport_errors': receiver.errors, 'local_queue_drops': receiver.dropped,
        'connections': receiver.connections, 'rejected_connections': receiver.rejected,
        'excluded_non_trial_events': excluded, 'production_network_events_emitted': 0}, indent=2) + '\n')
    print(json.dumps({'containers': len(rows), 'events': len(events), 'excluded': excluded,
                      'deliveries': len(listeners.records)}))


if __name__ == '__main__':
    main()
