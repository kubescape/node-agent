"""Follow repeated trial with two overlapping workloads and an excluded Pod."""
import concurrent.futures,json,pathlib,subprocess,time
from trial import CANARY,K,query,run_pod

base=pathlib.Path('/home/ubuntu/gvisor-trial/integration-20261102')
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
    rows=list(pool.map(run_pod,['integration-parallel-a-20261102','integration-parallel-b-20261102']))
(base/'evidence/concurrent-ledger.json').write_text(json.dumps(rows,indent=2)+'\n')
namespace='gvisor-excluded-20261102'
result=subprocess.run(K+['create','namespace',namespace],capture_output=True,timeout=20)
if result.returncode:raise RuntimeError('cannot create fresh excluded namespace')
excluded=run_pod('integration-excluded-20261102',namespace=namespace)
(base/'evidence/excluded-ledger.json').write_text(json.dumps([excluded],indent=2)+'\n')
time.sleep(7)
print('Concurrent and excluded workloads completed')
