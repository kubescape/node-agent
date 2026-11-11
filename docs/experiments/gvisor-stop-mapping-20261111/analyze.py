"""Check a candidate init-task stop mapping against independent CRI records.

The analysis never emits a stop event. It applies one candidate rule offline
and reports, per container, whether the rule agrees with CRI:

  A terminal candidate is a task_exit or exit_notify_parent record whose
  (context container ID, thread group ID, thread group start time) equals the
  key of that container's container/start claim, and whose thread ID is the
  thread group leader. Both point types for one key count as one termination.
"""
import argparse
import datetime
import json
import pathlib
import re

CASES = {'normal_exit', 'short_lived', 'graceful_stop', 'term_default', 'grace_timeout', 'forced_kill',
         'exec_session', 'sentry_failure', 'multi_container', 'concurrent', 'restart_in_sandbox',
         'receiver_restart'}
# Containers whose terminal record is expected to be missing, and why.
EXPECTED_LOSS = {('sentry_failure', 'workload'): 'sentry_killed',
                 ('receiver_restart', 'connected_before_restart'): 'stream_lost_on_receiver_restart'}
ALLOWED = {'kind', 'message_type', 'connection', 'receiver_generation', 'sender_cumulative_drops',
           'source_time_ns', 'thread_id', 'thread_start_time_ns', 'thread_group_id',
           'thread_group_start_time_ns', 'context_container_id', 'container_id', 'wait_status', 'observed_ns'}
TERMINAL = ('task_exit', 'exit_notify_parent')


def exit_code(status):
    """Map a wait(2)-style status to the code CRI reports (128+signal when signalled)."""
    signal = status & 0x7f
    return (status >> 8) & 0xff if signal == 0 else 128 + signal


def rfc3339_ns(value):
    m = re.fullmatch(r'(.+T\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)', value)
    if not m:
        raise ValueError('unexpected timestamp')
    zone = '+00:00' if m.group(3) == 'Z' else m.group(3)
    base = datetime.datetime.fromisoformat(m.group(1) + zone)
    return int(base.timestamp()) * 10**9 + int((m.group(2) or '0').ljust(9, '0'))


def key(event):
    return (event.get('context_container_id'), event.get('thread_group_id'),
            event.get('thread_group_start_time_ns'))


def analyze(rows, events, counters):
    if {r['case'] for r in rows} != CASES:
        raise ValueError('incomplete case matrix')
    if len({r['container_id'] for r in rows}) != len(rows):
        raise ValueError('duplicate container identity')
    if counters['local_queue_drops'] or counters['production_stop_events_emitted'] or counters['decode_or_transport_errors']:
        raise ValueError('invalid research receiver accounting')
    if any(set(e) - ALLOWED for e in events):
        raise ValueError('unapproved retained event field')
    if any(r['runtime_state'] != 'CONTAINER_EXITED' for r in rows):
        raise ValueError('missing CRI termination')

    containers = {r['container_id'] for r in rows}
    sandboxes = {r['sandbox_id'] for r in rows}
    starts = {}
    for e in events:
        if e['kind'] == 'container_start_claim':
            if e.get('container_id') != e.get('context_container_id'):
                raise ValueError('start claim context does not match its container ID')
            starts.setdefault(e['container_id'], []).append(e)

    # Apply the candidate rule to every retained record, independent of the ledger.
    candidates = {}
    for e in events:
        if e['kind'] not in TERMINAL:
            continue
        cid = e.get('context_container_id')
        claim = starts.get(cid)
        if not claim or len(claim) != 1:
            continue
        if key(e) == key(claim[0]) and e.get('thread_id') == e.get('thread_group_id'):
            candidates.setdefault(cid, []).append(e)

    findings = []
    for r in rows:
        cid = r['container_id']
        claim = starts.get(cid, [])
        if len(claim) != 1:
            raise ValueError('expected exactly one start claim per container')
        claim = claim[0]
        records = candidates.get(cid, [])
        kinds = sorted(e['kind'] for e in records)
        statuses = {e['wait_status'] for e in records}
        others = [e for e in events if e['kind'] == 'task_exit' and e.get('context_container_id') == cid
                  and key(e) != key(claim)]
        finished = rfc3339_ns(r['finished_at'])
        first = min((e['source_time_ns'] for e in records), default=None)
        loss = EXPECTED_LOSS.get((r['case'], r['role']))
        row = {
            'case': r['case'], 'role': r['role'], 'cri_exit_code': r['exit_code'],
            'start_thread_group_id': claim['thread_group_id'],
            'terminal_records': kinds,
            'terminations_after_dedup': 1 if records else 0,
            'status_consistent_across_points': len(statuses) <= 1,
            'derived_exit_code': exit_code(records[0]['wait_status']) if records else None,
            'other_task_exits_in_container': len(others),
            'other_task_exits_after_terminal': sum(1 for e in others if first and e['source_time_ns'] > first),
            'cri_finished_minus_source_ms': round((finished - first) / 1e6, 1) if first else None,
            'notify_minus_task_exit_us': round((next(e['source_time_ns'] for e in records if e['kind'] == 'exit_notify_parent')
                                                - next(e['source_time_ns'] for e in records if e['kind'] == 'task_exit')) / 1e3, 1)
                                          if len(records) == 2 else None,
            'cri_running_samples_after_terminal': sum(1 for s in r['running_samples_ns'] if first and s > first),
            'expected_loss': loss,
        }
        row['agrees_with_cri'] = (row['derived_exit_code'] == r['exit_code']) if records else None
        if loss and records:
            raise ValueError('expected loss case unexpectedly produced a terminal record')
        if not loss and (kinds != ['exit_notify_parent', 'task_exit'] or not row['agrees_with_cri']
                         or not row['status_consistent_across_points']):
            raise ValueError('candidate mapping disagrees with CRI for ' + r['case'] + '/' + r['role'])
        findings.append(row)

    # Records the rule must not turn into container stops.
    sandbox_exits = [e for e in events if e['kind'] in TERMINAL and e.get('context_container_id') in sandboxes]
    unmatched = [e for e in events if e['kind'] in TERMINAL and e.get('context_container_id') not in containers | sandboxes]
    # The pause container's init also matches the rule; only runtime inventory
    # (sandbox ID vs container ID) tells a sandbox teardown from a container stop.
    sandbox_candidates = [cid for cid in candidates if cid in sandboxes]
    false_candidates = [cid for cid in candidates if cid not in containers | sandboxes]
    if false_candidates or unmatched:
        raise ValueError('candidate rule matched a non-workload record')

    exec_row = next(r for r in rows if r['case'] == 'exec_session')
    restart = {r['role']: r for r in findings if r['case'] == 'restart_in_sandbox'}
    claimed_groups = [f['start_thread_group_id'] for f in findings]
    observed = [f for f in findings if f['terminations_after_dedup']]
    return {
        'containers': len(findings),
        'terminal_observed': len(observed),
        'terminal_agrees_with_cri': sum(1 for f in observed if f['agrees_with_cri']),
        'terminal_missing_expected_loss': sum(1 for f in findings if f['expected_loss']),
        'sandbox_teardown_records_excluded': len(sandbox_exits),
        'sandboxes_matching_rule_without_inventory': len(sandbox_candidates),
        'non_init_task_exits_excluded': sum(f['other_task_exits_in_container'] for f in findings),
        'non_init_exits_after_init_exit': sum(f['other_task_exits_after_terminal'] for f in findings),
        'exec_session_exit_left_container_running': exec_row['running_after_exec_exit'],
        'claimed_thread_group_ids_reused_across_containers': len(set(claimed_groups)) < len(claimed_groups),
        'restart_instances_thread_groups': [restart['first_instance']['start_thread_group_id'],
                                            restart['second_instance']['start_thread_group_id']],
        'max_cri_finished_minus_source_ms': max(f['cri_finished_minus_source_ms'] for f in observed),
        'cri_running_samples_after_terminal': sum(f['cri_running_samples_after_terminal'] for f in observed),
        'notify_minus_task_exit_us_range': [min(f['notify_minus_task_exit_us'] for f in observed),
                                            max(f['notify_minus_task_exit_us'] for f in observed)],
        'cases': findings,
        'production_stop_events_emitted': 0,
    }


def load(root):
    return (json.loads((root / 'runtime-ledger.json').read_text()),
            json.loads((root / 'events.json').read_text()),
            json.loads((root / 'receiver.json').read_text()))


def main():
    p = argparse.ArgumentParser()
    p.add_argument('directory')
    args = p.parse_args()
    root = pathlib.Path(args.directory)
    summary = analyze(*load(root))
    (root / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({k: v for k, v in summary.items() if k != 'cases'}, indent=2))


if __name__ == '__main__':
    main()
