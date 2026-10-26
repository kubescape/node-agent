import importlib.util,json,pathlib,subprocess,time,sys
base=pathlib.Path('/home/ubuntu/gvisor-trial')
spec=importlib.util.spec_from_file_location('trial_helpers',base/'trial-helpers.py')
trial=importlib.util.module_from_spec(spec);spec.loader.exec_module(trial)
out=base/'loss-investigation'/sys.argv[1]
out.mkdir(mode=0o700,parents=True,exist_ok=False)
trial.OUT=out
popen=subprocess.Popen
def instrument(args,*more,**options):
 if args[0]=='gvisor-start-probe':
  args=[str(base/'gvisor-start-probe-fixed'),'--diagnostics',*args[1:]]
 return popen(args,*more,**options)
subprocess.Popen=instrument
ids=['loss-check-%02d'%i for i in range(1,21)]
record={'case':sys.argv[1],'inventory':[trial.create(id) for id in ids],'starts':[]}
(out/'ledger.json').write_text(json.dumps(record,indent=2)+'\n')
probe=trial.probe_start('starts',ids)
try:
 for id in ids:
  result=trial.task_start(id);record['starts'].append(result)
  (out/'ledger.json').write_text(json.dumps(record,indent=2)+'\n')
  assert result['exit']==0
  trial.wait_stopped([id]);trial.cleanup(id)
 time.sleep(.2)
finally:trial.probe_stop(probe)
record['evidence']=trial.evidence('starts',ids)
record['health']=json.loads((out/'starts.stderr').read_text())
(out/'ledger.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps({'case':sys.argv[1],'evidence':record['evidence'],'health':record['health']},indent=2),flush=True)
