"""Run only on the dedicated disposable K3s VM, after source/collector setup.

Creates harmless, digest-pinned workloads. Never retain raw Pod/OCI specs or
errors as evidence; they can contain the synthetic argv/cwd privacy marker.
"""
import argparse,json,pathlib,socket,struct,subprocess,time

CANARY='GVS_INTEGRATION_CANARY_2026'
IMAGE='docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662'
NS='gvisor-comparison'
K=['k3s','kubectl','--request-timeout=15s']


def query(args):
    result=subprocess.run(args,capture_output=True,text=True,timeout=20)
    if result.returncode:raise RuntimeError('experiment query failed')
    return json.loads(result.stdout)


def readiness():
    client=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    client.settimeout(3)
    client.connect('/run/kubescape/gvisor-events.sock')
    client.send(b'\x08\x01')
    assert client.recv(32)==b'\x08\x01'
    return client


def workload(name,namespace=NS,ordinary=False):
    spec={'restartPolicy':'Never','containers':[{'name':'workload','image':IMAGE,'imagePullPolicy':'IfNotPresent','command':['/bin/sh','-c','sleep 4',CANARY],'workingDir':'/'+CANARY,'volumeMounts':[{'name':'private-cwd','mountPath':'/'+CANARY}],'resources':{'limits':{'cpu':'500m','memory':'256Mi'}}}],'volumes':[{'name':'private-cwd','emptyDir':{}}]}
    if not ordinary:spec['runtimeClassName']='gvisor'
    return {'apiVersion':'v1','kind':'Pod','metadata':{'name':name,'namespace':namespace},'spec':spec}


def run_pod(name,namespace=NS,ordinary=False):
    result=subprocess.run(K+['create','-f','-'],input=json.dumps(workload(name,namespace,ordinary)),capture_output=True,text=True,timeout=20)
    if result.returncode:raise RuntimeError('cannot create fresh experiment Pod')
    deadline=time.monotonic()+90
    while True:
        pod=query(K+['get','pod',name,'-n',namespace,'-o','json'])
        statuses=pod.get('status',{}).get('containerStatuses',[])
        if statuses and 'terminated' in statuses[0].get('state',{}):
            status=statuses[0];end=status['state']['terminated'];id=status['containerID'].split('://',1)[1]
            info=query(['k3s','ctr','-n','k8s.io','containers','info',id])
            containers=query(['k3s','crictl','ps','-a','--id',id,'-o','json'])['containers']
            assert len(containers)==1 and containers[0]['id']==id
            return {'name':name,'namespace':namespace,'pod_uid':pod['metadata']['uid'],'container_id':id,'sandbox_id':containers[0]['podSandboxId'],'runtime':info['Runtime']['Name'],'exit_code':end['exitCode'],'image_id':status['imageID']}
        if time.monotonic()>deadline:raise RuntimeError('experiment Pod did not complete')
        time.sleep(.25)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True);parser.add_argument('--count',type=int,default=20);args=parser.parse_args()
    out=pathlib.Path(args.output);out.mkdir(mode=0o700,exist_ok=False)
    # The trace sink and listener must complete a real handshake before start.
    readiness().close()
    results=[]
    try:
        for index in range(1,args.count+1):
            results.append(run_pod('integration-20261102-%02d'%index))
            (out/'runtime-ledger.json').write_text(json.dumps(results,indent=2)+'\n')
            assert results[-1]['exit_code']==0
        # A valid frame claiming an ID absent from the runtime must not export.
        client=readiness();unknown=b'd'*64
        assert not query(['k3s','crictl','ps','-a','--id',unknown.decode(),'-o','json'])['containers']
        client.send(struct.pack('<HHI',8,1,0)+b'\x12'+bytes([len(unknown)])+unknown);client.close()
        results.append(run_pod('integration-ordinary-20261102',ordinary=True))
        (out/'runtime-ledger.json').write_text(json.dumps(results,indent=2)+'\n')
        time.sleep(7) # bounded OTEL batch-export observation interval
    finally:
        (out/'runtime-ledger.json').write_text(json.dumps(results,indent=2)+'\n')
    print('Workloads completed; compare the sanitized collector output with the runtime ledger')


if __name__=='__main__':main()
