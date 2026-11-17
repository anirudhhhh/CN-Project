"""Three independent OS processes, using alternate ports on one test host."""
import json
from pathlib import Path
import subprocess
import sys
import time
import urllib.request
ROOT=Path(__file__).resolve().parents[1]
processes=[]
def get(port,path='/'):
    return urllib.request.urlopen(f'http://127.0.0.1:{port}{path}',timeout=2)
def post(port,path,data):
    r=urllib.request.Request(f'http://127.0.0.1:{port}{path}',data=json.dumps(data).encode(),headers={'Content-Type':'application/json'})
    return json.load(urllib.request.urlopen(r,timeout=15))
try:
    for role,web in [('vpn',5152),('receiver',5153),('sender',5151)]:
        p=subprocess.Popen([sys.executable,'showcase/app.py','--role',role,'--bind','127.0.0.1','--web-port',str(web),'--vpn-port','9190','--receiver-port','8100'],cwd=ROOT,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        processes.append(p)
        for attempt in range(60):
            try:
                assert get(web).status==200
                break
            except Exception:
                if p.poll() is not None: raise RuntimeError(f'{role} exited during startup')
                time.sleep(.1)
        else: raise RuntimeError(f'{role} did not start')
    post(5153,'/api/receiver/config',{'vpn':'127.0.0.1'})
    r=post(5151,'/api/send',{'vpn':'127.0.0.1:9190','address':'127.0.0.1:8100','message':'Three independent processes: hello! नमस्ते'})
    assert r['ok'],r
    received=json.load(get(5153,'/api/receiver'))['packets'][0]
    observed=json.load(get(5152,'/api/server'))['events']
    assert received['message']==r['sent']
    outgoing=next(e for e in observed if e['stage']=='outbound_connected')
    assert received['peer']==':'.join(map(str,outgoing['outbound_local']))
    assert any(e.get('encoded_hex') for e in observed)
    post(5153,'/api/receiver/config',{'vpn':'127.0.0.2'})
    r=post(5151,'/api/send',{'vpn':'127.0.0.1:9190','address':'127.0.0.1:8100','message':'Must be rejected'})
    assert not r['ok']
    assert len(json.load(get(5153,'/api/receiver'))['packets'])==1
    print('PASS: independent sender, VPN and receiver processes; real forwarding, server capture, receiver source check and rejection')
finally:
    for p in processes: p.terminate()
    for p in processes:
        try:p.wait(timeout=5)
        except subprocess.TimeoutExpired:p.kill()
