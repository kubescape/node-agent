"""Cross-check exported observations using retained Pods and CRI inventory.

Run before deleting the experiment Pods. Only allowlisted fields leave memory.
"""
import collections,json,pathlib,subprocess
from trial import CANARY,K,query

base=pathlib.Path('/home/ubuntu/gvisor-trial/integration-20261102')
source=base/'evidence'
rows=[]
for name in ['runtime-ledger','concurrent-ledger','excluded-ledger']:
    rows.extend(json.loads((source/(name+'.json')).read_text()))
for row in rows:
    cri=query(['k3s','crictl','ps','-a','--id',row['container_id'],'-o','json'])['containers']
    assert len(cri)==1 and cri[0]['id']==row['container_id']
    row['sandbox_id']=cri[0]['podSandboxId']
    pod=query(K+['get','pod',row['name'],'-n',row['namespace'],'-o','json'])
    assert pod['metadata']['uid']==row['pod_uid']
    state=pod['status']['containerStatuses'][0]['state']['terminated']
    row['started_at']=state['startedAt'];row['finished_at']=state['finishedAt']
    assert row['exit_code']==0
raw=(base/'observations.jsonl').read_bytes()
assert CANARY.encode() not in raw
observations=[json.loads(line) for line in raw.splitlines()]
expected={r['container_id']:r for r in rows if r['runtime']=='io.containerd.runsc.v1' and r['namespace']=='gvisor-comparison'}
counts=collections.Counter(o['container.id'] for o in observations)
assert set(counts)==set(expected) and all(n==1 for n in counts.values())
for event in observations:
    row=expected[event['container.id']]
    assert event['source']=='gvisor_trace' and event['body']=='RuntimeObservation'
    assert event['kind']=='container_started' and event['identity_status']=='verified'
    assert event['identity_origin']=='local_cri_and_kubernetes'
    assert event['pod_name']==row['name'] and event['pod_uid']==row['pod_uid']
    assert event['sandbox_id']==row['sandbox_id'] and event['namespace']==row['namespace']
    assert event['container_name']=='workload' and event['node']=='gvisor-trial'
    assert event['sender_reported_drops']==0
    assert event['wire_canary_found'] is False and event['unexpected_attribute_count']==0
parallel=[r for r in rows if r['name'].startswith('integration-parallel-')]
assert len(parallel)==2 and max(r['started_at'] for r in parallel)<min(r['finished_at'] for r in parallel)
logs=subprocess.check_output(K+['logs','-n','kubescape','daemonset/node-agent'])
assert CANARY.encode() not in logs
result={'repeated_expected':20,'repeated_exported':sum(1 for o in observations if o['pod_name'].startswith('integration-20261102-')),'concurrent_expected':2,'concurrent_exported':sum(1 for o in observations if o['pod_name'].startswith('integration-parallel-')),'concurrent_execution_overlap':True,'excluded_namespace_exports':sum(o['namespace']!='gvisor-comparison' for o in observations),'unknown_id_exports':counts.get('d'*64,0),'ordinary_runtime_exports':sum(counts.get(r['container_id'],0) for r in rows if r['runtime']!='io.containerd.runsc.v1'),'literal_canary_in_exports_or_agent_logs':False,'wire_privacy_checks_before_filtering':True,'unexpected_observation_attributes':0,'identity_cross_checks':'exact container ID, sandbox ID, Pod UID/name/namespace, node, container name'}
assert result['repeated_exported']==20 and result['concurrent_exported']==2
for name,value in [('verified-runtime-ledger',rows),('verification',result)]:
    text=json.dumps(value,indent=2)+'\n';assert CANARY not in text
    with (source/(name+'.json')).open('x') as output:output.write(text)
print(json.dumps(result,indent=2))
