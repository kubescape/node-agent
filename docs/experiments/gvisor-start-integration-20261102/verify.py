"""Cross-check exported observations using retained Pods and CRI inventory.

Run before deleting the experiment Pods. Only allowlisted fields leave memory.
Validation remains active under python -O and PYTHONOPTIMIZE.
"""
import collections
from datetime import datetime
import json
import pathlib
import subprocess
from trial import CANARY, K, query


def require(condition, message):
    if not condition:
        raise ValueError(message)


def timestamp(value):
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except (ValueError, AttributeError):
        raise ValueError('invalid runtime timestamp') from None
    require(parsed.tzinfo is not None, 'runtime timestamp requires a timezone')
    return parsed


def verify(rows, raw, logs):
    canary_found = CANARY.encode() in raw or CANARY.encode() in logs
    require(not canary_found, 'privacy marker found in retained output')
    observations = [json.loads(line) for line in raw.splitlines()]
    expected = {r['container_id']: r for r in rows
                if r['runtime'] == 'io.containerd.runsc.v1' and r['namespace'] == 'gvisor-comparison'}
    counts = collections.Counter(o['container.id'] for o in observations)
    require(set(counts) == set(expected) and all(n == 1 for n in counts.values()),
            'observation identities or counts do not match runtime inventory')
    for event in observations:
        row = expected[event['container.id']]
        require(event['source'] == 'gvisor_trace' and event['body'] == 'RuntimeObservation', 'unexpected observation source')
        require(event['kind'] == 'container_started' and event['identity_status'] == 'verified', 'unexpected observation semantics')
        require(event['identity_origin'] == 'local_cri_and_kubernetes', 'unexpected identity origin')
        require(event['pod_name'] == row['name'] and event['pod_uid'] == row['pod_uid'], 'Pod identity mismatch')
        require(event['sandbox_id'] == row['sandbox_id'] and event['namespace'] == row['namespace'], 'sandbox identity mismatch')
        require(event['container_name'] == 'workload' and event['node'] == 'gvisor-trial', 'container or node mismatch')
        require(event['sender_reported_drops'] == 0, 'sender reported event loss')
    parallel = [r for r in rows if r['name'].startswith('integration-parallel-')]
    overlap = (len(parallel) == 2 and
               max(timestamp(r['started_at']) for r in parallel) < min(timestamp(r['finished_at']) for r in parallel))
    wire_checks = bool(observations) and all(o['wire_canary_found'] is False for o in observations)
    unexpected = sum(o['unexpected_attribute_count'] for o in observations)
    require(overlap, 'concurrent workload execution did not overlap')
    require(wire_checks and all(o['unexpected_attribute_count'] == 0 for o in observations), 'wire privacy check failed')
    result = {
        'repeated_expected': 20,
        'repeated_exported': sum(o['pod_name'].startswith('integration-20261102-') for o in observations),
        'concurrent_expected': 2,
        'concurrent_exported': sum(o['pod_name'].startswith('integration-parallel-') for o in observations),
        'concurrent_execution_overlap': overlap,
        'excluded_namespace_exports': sum(o['namespace'] != 'gvisor-comparison' for o in observations),
        'unknown_id_exports': counts.get('d' * 64, 0),
        'ordinary_runtime_exports': sum(counts.get(r['container_id'], 0) for r in rows if r['runtime'] != 'io.containerd.runsc.v1'),
        'literal_canary_in_exports_or_agent_logs': canary_found,
        'wire_privacy_checks_before_filtering': wire_checks,
        'unexpected_observation_attributes': unexpected,
        'identity_cross_checks': 'exact container ID, sandbox ID, Pod UID/name/namespace, node, container name',
    }
    require(result['repeated_exported'] == 20 and result['concurrent_exported'] == 2, 'unexpected experiment totals')
    return result


def main():
    base = pathlib.Path('/home/ubuntu/gvisor-trial/integration-20261102')
    source = base / 'evidence'
    rows = []
    for name in ['runtime-ledger', 'concurrent-ledger', 'excluded-ledger']:
        rows.extend(json.loads((source / (name + '.json')).read_text()))
    for row in rows:
        cri = query(['k3s', 'crictl', 'ps', '-a', '--id', row['container_id'], '-o', 'json'])['containers']
        require(len(cri) == 1 and cri[0]['id'] == row['container_id'], 'CRI identity mismatch')
        row['sandbox_id'] = cri[0]['podSandboxId']
        pod = query(K + ['get', 'pod', row['name'], '-n', row['namespace'], '-o', 'json'])
        require(pod['metadata']['uid'] == row['pod_uid'], 'Pod UID changed')
        state = pod['status']['containerStatuses'][0]['state']['terminated']
        row['started_at'] = state['startedAt']
        row['finished_at'] = state['finishedAt']
        require(row['exit_code'] == 0 and state['exitCode'] == 0, 'workload did not succeed')
    result = verify(rows, (base / 'observations.jsonl').read_bytes(),
                    subprocess.check_output(K + ['logs', '-n', 'kubescape', 'daemonset/node-agent']))
    for name, value in [('verified-runtime-ledger', rows), ('verification', result)]:
        text = json.dumps(value, indent=2) + '\n'
        require(CANARY not in text, 'privacy marker found in verification output')
        with (source / (name + '.json')).open('x') as output:
            output.write(text)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
