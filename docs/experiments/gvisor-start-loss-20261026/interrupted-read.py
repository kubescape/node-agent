import argparse,ctypes,json,pathlib,signal,socket,struct,subprocess,time
parser=argparse.ArgumentParser()
parser.add_argument('--probe',required=True)
parser.add_argument('--output',required=True)
args=parser.parse_args()
base=pathlib.Path('/home/ubuntu/gvisor-trial')
out=pathlib.Path(args.output)
out.mkdir(mode=0o700)
path='/run/kubescape/gvisor-interrupt.sock'
libc=ctypes.CDLL(None,use_errno=True)
with (out/'starts.jsonl').open('w') as stdout,(out/'health.jsonl').open('w') as stderr:
 probe=subprocess.Popen([args.probe,'--diagnostics','--socket',path,'--container-id','verified-trial-id'],stdout=stdout,stderr=stderr)
 try:
  deadline=time.monotonic()+5
  while True:
   try:
    client=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    client.settimeout(2);client.connect(path);break
   except OSError:
    client.close()
    if time.monotonic()>deadline:raise
    time.sleep(.02)
  client.send(b'\x08\x01');assert client.recv(32)==b'\x08\x01'
  time.sleep(.1)
  for _ in range(10):
   for tid in pathlib.Path('/proc/'+str(probe.pid)+'/task').iterdir():
    libc.tgkill(probe.pid,int(tid.name),signal.SIGURG)
   time.sleep(.02)
  id=b'verified-trial-id'
  packet=struct.pack('<HHI',8,1,0)+b'\x12'+bytes([len(id)])+id
  try:client.send(packet);result='sent'
  except OSError as error:result=type(error).__name__
  client.close();time.sleep(.2)
 finally:
  probe.send_signal(signal.SIGTERM);probe.wait(timeout=5)
print(json.dumps({'send':result,'records':len((out/'starts.jsonl').read_text().splitlines()),'health':json.loads((out/'health.jsonl').read_text())},indent=2))
