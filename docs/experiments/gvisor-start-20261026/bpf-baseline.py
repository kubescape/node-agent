"""Recorded live experiment fixture; run only in the dedicated disposable VM.

Requires the setup documented in README.md. This is not production collection.
"""
import datetime, json, pathlib, signal, subprocess, time
BASE = pathlib.Path('/home/ubuntu/gvisor-trial')
OUT = BASE / 'evidence'
NS = 'gvisor-trial'
ROOT = '/opt/gvisor-trial/rootfs'
program = 'BEGIN { printf("READY\\n"); } tracepoint:syscalls:sys_enter_execve /str(args->filename) == "/bin/busybox"/ { printf("%llu %d %s\\n", nsecs, pid, str(args->filename)); }'
results = []

def ctr(*args, check=True):
    return subprocess.run(['ctr', '--namespace', NS, *args], capture_output=True, text=True, timeout=30, check=check)
for (label, runtime) in [('ordinary', 'io.containerd.runc.v2'), ('gvisor', 'io.containerd.runsc.v1')]:
    id = 'bpf-baseline-' + label
    args = ['containers', 'create', '--rootfs', '--runtime', runtime]
    if label == 'gvisor':
        config = BASE / 'runsc-bpf.toml'
        config.write_text('[runsc_config]\nplatform = "systrap"\n')
        args += ['--runtime-config-path', str(config)]
    args += [ROOT, id, '/bin/sh', '-c', '/bin/busybox true; /bin/busybox true; /bin/busybox true; sleep 1']
    ctr(*args)
    record = {'scenario': label, 'runtime': runtime, 'id': id, 'expected_guest_exec_calls': 3}
    trace_file = OUT / (label + '-host-exec.txt')
    errors = OUT / (label + '-bpf.stderr')
    with trace_file.open('w') as stdout, errors.open('w') as stderr:
        tracer = subprocess.Popen(['bpftrace', '-q', '-e', program], stdout=stdout, stderr=stderr)
        try:
            deadline = time.monotonic() + 15
            while 'READY' not in trace_file.read_text():
                if tracer.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('host BPF tracer unavailable: ' + errors.read_text())
                time.sleep(0.1)
            record['start_requested_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            started = ctr('tasks', 'start', '--detach', id, check=False)
            record['start_exit'] = started.returncode
            record['start_error'] = started.stderr
            time.sleep(3)
            record['runtime_state'] = ctr('tasks', 'list').stdout
        finally:
            tracer.send_signal(signal.SIGINT)
            tracer.wait(timeout=10)
            ctr('tasks', 'kill', '--signal', 'SIGKILL', id, check=False)
            ctr('tasks', 'delete', id, check=False)
            ctr('containers', 'delete', id, check=False)
    record['tracer_exit'] = tracer.returncode
    record['observed_host_exec_calls'] = sum(('/bin/busybox' in line for line in trace_file.read_text().splitlines()))
    results.append(record)
    print(json.dumps(record), flush=True)
(OUT / 'host-bpf-results.json').write_text(json.dumps(results, indent=2) + '\n')
