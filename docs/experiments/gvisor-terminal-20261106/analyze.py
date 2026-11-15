"""Verify retained research evidence without emitting production stop events."""
import argparse
import json
import pathlib


def analyze(rows, events, counters):
    by_case={r['case']:r for r in rows}
    if set(by_case)!={'normal_exit','forced_kill','receiver_disconnect'} or len(rows)!=3:
        raise ValueError('incomplete case matrix')
    if len({r['container_id'] for r in rows})!=3:
        raise ValueError('duplicate container identity')
    if counters['local_queue_drops'] or counters['production_stop_events_emitted']:
        raise ValueError('invalid research receiver accounting')
    allowed={'kind','message_type','sender_cumulative_drops','source_time_ns','thread_id','thread_group_id','context_container_id','container_id','wait_status','observed_ns'}
    if any(set(e)-allowed for e in events):raise ValueError('unapproved retained event field')
    findings=[]
    for case in ['normal_exit','forced_kill','receiver_disconnect']:
        row=by_case[case];cid=row['container_id']
        starts=[e for e in events if e['kind']=='container_start_claim' and e.get('container_id')==cid]
        if len(starts)!=1 or row['runtime_state']!='CONTAINER_EXITED':
            raise ValueError('missing start or CRI termination')
        if row['exit_code']!=(7 if case=='normal_exit' else 137):
            raise ValueError('unexpected CRI exit code')
        init=starts[0]['thread_group_id']
        tasks=[e for e in events if e['kind']=='task_exit' and e.get('context_container_id')==cid]
        init_exits=[e for e in tasks if e.get('thread_group_id')==init and e.get('thread_id')==starts[0]['thread_id']]
        children=[e for e in tasks if e.get('thread_group_id')!=init]
        expected_status=7<<8 if case=='normal_exit' else 9
        matching=bool(init_exits) and all(e.get('wait_status',0)==expected_status for e in init_exits)
        running_after_child=any(e['source_time_ns'] < sample < parent['source_time_ns']
                                for e in children for sample in row['running_samples_ns'] for parent in init_exits)
        findings.append({'case':case,'cri_exit_code':row['exit_code'],'task_exit_count':len(tasks),
                         'initial_thread_group':init,'init_task_exit_count':len(init_exits),
                         'init_wait_status_matches_cri_case':matching,
                         'non_init_task_exit_count':len(children),
                         'cri_running_sample_after_child_exit':running_after_child,
                         'running_after_receiver_disconnect':row['running_after_receiver_disconnect']})
    if not findings[0]['cri_running_sample_after_child_exit'] or not findings[2]['running_after_receiver_disconnect']:
        raise ValueError('nonterminal controls were not demonstrated')
    return {'cases':findings,'production_stop_events_emitted':0,
            'container_stop_contract_ready':False,
            'reason':'task points require verified init-task mapping, deduplication and runtime reconciliation; disconnect is nonterminal'}


def main():
    p=argparse.ArgumentParser();p.add_argument('directory');args=p.parse_args()
    root=pathlib.Path(args.directory)
    rows=json.loads((root/'runtime-ledger.json').read_text())
    events=json.loads((root/'events.json').read_text())
    counters=json.loads((root/'receiver.json').read_text())
    summary=analyze(rows,events,counters)
    (root/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary))


if __name__=='__main__':main()
