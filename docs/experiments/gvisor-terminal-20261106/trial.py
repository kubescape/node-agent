#!/usr/bin/env python3
"""Disposable Linux/K3s research receiver, not a node-agent event source.

Wire schema: google/gvisor release-20261019.0 common.proto and sentry.proto.
Retains only numeric context, claimed IDs and exit status. Never logs a raw
frame, command, working directory, environment or API error response.
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
CANARY = 'GVS_TERMINAL_CANARY_2026'
IMAGE = 'docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662'
NS = 'gvisor-terminal-20261106'
K = ['k3s','kubectl','--request-timeout=15s']


def require(ok, message):
    if not ok: raise ValueError(message)


def varint(data, pos):
    value = 0
    for index in range(10):
        require(pos < len(data), 'truncated protobuf')
        byte = data[pos]; pos += 1
        require(index != 9 or byte < 2, 'overflowing protobuf')
        value |= (byte & 127) << (7*index)
        if not byte & 128: return value, pos
    raise ValueError('invalid protobuf')


def fields(data):
    require(len(data) <= LIMIT, 'oversized protobuf')
    pos = 0
    while pos < len(data):
        tag,pos = varint(data,pos); number,kind = tag >> 3, tag & 7
        require(number > 0, 'invalid protobuf tag')
        if kind == 0: value,pos = varint(data,pos)
        elif kind == 2:
            size,pos = varint(data,pos)
            require(size <= len(data)-pos, 'truncated protobuf field')
            value = data[pos:pos+size]; pos += size
        elif kind in (1,5):
            size = 8 if kind == 1 else 4
            require(size <= len(data)-pos, 'truncated fixed field')
            value = data[pos:pos+size]; pos += size
        else: raise ValueError('unsupported protobuf wire kind')
        yield number,kind,value


def identity(data):
    value = bytes(data).decode('ascii')
    require(len(value)==64 and all(c in '0123456789abcdef' for c in value), 'invalid claimed ID')
    return value


def decode(frame):
    require(8 <= len(frame) <= LIMIT, 'invalid frame length')
    header,kind,drops = struct.unpack_from('<HHI',frame)
    require(8 <= header <= len(frame), 'invalid header')
    if kind not in (1,4,5): return None
    row={'kind':{1:'container_start_claim',4:'exit_notify_parent',5:'task_exit'}[kind],
         'message_type':kind,'sender_cumulative_drops':drops}
    if kind in (4,5):row['wait_status']=0  # protobuf's omitted scalar default
    for number,wire,value in fields(frame[header:]):
        if number==1 and wire==2:
            for n,w,v in fields(value):
                if n==6 and w==2: row['context_container_id']=identity(v)
                elif n in (1,2,4) and w==0: row[{1:'source_time_ns',2:'thread_id',4:'thread_group_id'}[n]]=v
        elif number==2 and kind==1 and wire==2:row['container_id']=identity(value)
        elif number==2 and kind in (4,5) and wire==0:row['wait_status']=value
    row['observed_ns']=time.time_ns()
    return row


class Receiver:
    def __init__(self,path):
        self.path=path; self.events=[]; self.lock=threading.Lock();self.closed=threading.Event()
        self.clients=[];self.workers=[];self.errors=0;self.dropped=0
        parent=pathlib.Path(path).parent
        parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        require(parent.stat().st_uid==os.geteuid() and parent.stat().st_mode & 0o77==0,'private receiver directory required')
        require(not pathlib.Path(path).exists(),'socket already exists')
        self.listener=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        self.listener.bind(path);os.chmod(path,0o600);self.listener.listen(8);self.listener.settimeout(.2)
        self.worker=threading.Thread(target=self.accept);self.worker.start()

    def record(self,row):
        with self.lock:
            if len(self.events)<256:self.events.append(row)
            else:self.dropped+=1

    def accept(self):
        while not self.closed.is_set():
            try:client,_=self.listener.accept()
            except socket.timeout:continue
            except OSError:break
            with self.lock:
                if len(self.clients)>=16:client.close();continue
                self.clients.append(client)
            t=threading.Thread(target=self.receive,args=(client,));self.workers.append(t);t.start()

    def receive(self,client):
        client.settimeout(2)
        buffer=bytearray(LIMIT+1)
        try:
            require(client.recv(32)==b'\x08\x01','unsupported handshake')
            client.sendall(b'\x08\x01');client.settimeout(.2)
            while not self.closed.is_set():
                try:n,_,flags,_=client.recvmsg_into([buffer])
                except socket.timeout:continue
                if not n:break
                try:
                    require(not flags & socket.MSG_TRUNC and n<=LIMIT,'oversized packet')
                    event=decode(memoryview(buffer)[:n])
                    if event:self.record(event)
                finally:buffer[:n]=b'\0'*n
        except (OSError,ValueError,UnicodeError):
            with self.lock:self.errors+=1
        finally:
            buffer[:]=b'\0'*len(buffer);client.close()
            self.record({'kind':'source_disconnected','observed_ns':time.time_ns()})

    def disconnect(self):
        with self.lock: clients=list(self.clients)
        for client in clients:
            try:client.shutdown(socket.SHUT_RDWR)
            except OSError:pass

    def close(self):
        self.closed.set();self.disconnect();self.listener.close();self.worker.join(3)
        for worker in self.workers:worker.join(3)
        require(not self.worker.is_alive() and not any(t.is_alive() for t in self.workers),'receiver shutdown timed out')
        pathlib.Path(self.path).unlink(missing_ok=True)


def query(args,payload=None):
    r=subprocess.run(args,input=json.dumps(payload) if payload else None,capture_output=True,text=True,timeout=25)
    require(r.returncode==0,'runtime query failed (raw response suppressed)')
    return json.loads(r.stdout)


def pod(case):
    command='sleep 1; (sleep 1); wait; sleep 2; exit 7' if case=='normal_exit' else 'sleep 60'
    return {'apiVersion':'v1','kind':'Pod','metadata':{'name':'terminal-'+case.replace('_','-'),'namespace':NS,'labels':{'experiment':NS}},
            'spec':{'runtimeClassName':'gvisor','restartPolicy':'Never','containers':[{'name':'workload','image':IMAGE,
             'command':['/bin/sh','-c',command,CANARY],'workingDir':'/'+CANARY,
             'volumeMounts':[{'name':'cwd','mountPath':'/'+CANARY}],'resources':{'limits':{'cpu':'500m','memory':'256Mi'}}}],
             'volumes':[{'name':'cwd','emptyDir':{}}]}}


def run_case(case,receiver):
    obj=pod(case);name=obj['metadata']['name'];query(K+['create','-f','-','-o','json'],obj)
    end=time.monotonic()+60;cid=None
    while time.monotonic()<end:
        state=query(K+['get','pod',name,'-n',NS,'-o','json'])
        statuses=state.get('status',{}).get('containerStatuses',[])
        if statuses and statuses[0].get('containerID'):
            cid=statuses[0]['containerID'].split('://',1)[1];break
        time.sleep(.1)
    require(cid is not None,'container ID did not appear')
    before=query(['k3s','crictl','inspect',cid])['status']
    running_after_disconnect=None
    if case=='receiver_disconnect':
        receiver.disconnect();time.sleep(1)
        running_after_disconnect=query(['k3s','crictl','inspect',cid])['status']['state']=='CONTAINER_RUNNING'
        require(running_after_disconnect,'disconnect did not leave a running control')
    if case!='normal_exit':
        r=subprocess.run(['k3s','ctr','-n','k8s.io','tasks','kill','--signal','SIGKILL',cid],capture_output=True,timeout=15)
        require(r.returncode==0,'cannot terminate owned trial container')
    running_samples=[]
    while time.monotonic()<end:
        status=query(['k3s','crictl','inspect',cid])['status']
        if status['state']=='CONTAINER_EXITED':break
        if status['state']=='CONTAINER_RUNNING':running_samples.append(time.time_ns())
        time.sleep(.1)
    require(status['state']=='CONTAINER_EXITED','container did not exit')
    info=query(['k3s','crictl','ps','-a','--id',cid,'-o','json'])['containers']
    require(len(info)==1 and info[0]['id']==cid,'CRI identity mismatch')
    expected=7 if case=='normal_exit' else 137
    require(status['exitCode']==expected,'unexpected runtime exit code')
    time.sleep(.5)
    return {'case':case,'container_id':cid,'sandbox_id':info[0]['podSandboxId'],'pod_uid':state['metadata']['uid'],
            'runtime_state':status['state'],'exit_code':status['exitCode'],'started_at':status['startedAt'],
            'finished_at':status['finishedAt'],'running_samples_ns':running_samples,'running_after_receiver_disconnect':running_after_disconnect}


def main():
    global NS
    p=argparse.ArgumentParser();p.add_argument('--namespace',default=NS);p.add_argument('--output',required=True);p.add_argument('--socket',default='/run/kubescape/gvisor-terminal/events.sock');args=p.parse_args()
    require(args.namespace.startswith('gvisor-terminal-') and all(c in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in args.namespace), 'dedicated namespace required')
    NS=args.namespace
    out=pathlib.Path(args.output);out.mkdir(mode=0o700,exist_ok=False)
    query(K+['create','namespace',NS,'-o','json'])
    receiver=Receiver(args.socket);rows=[]
    try:
        for case in ['normal_exit','forced_kill','receiver_disconnect']:
            rows.append(run_case(case,receiver))
            (out/'runtime-ledger.json').write_text(json.dumps(rows,indent=2)+'\n')
    finally:receiver.close()
    events=receiver.events
    require(CANARY not in json.dumps(events),'sensitive marker retained')
    (out/'events.json').write_text(json.dumps(events,indent=2)+'\n')
    (out/'receiver.json').write_text(json.dumps({'decode_or_transport_errors':receiver.errors,'local_queue_drops':receiver.dropped,'production_stop_events_emitted':0},indent=2)+'\n')
    print(json.dumps({'cases':len(rows),'events':len(events),'production_stop_events_emitted':0}))


if __name__=='__main__':main()
