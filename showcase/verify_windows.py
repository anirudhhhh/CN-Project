import json
import urllib.request
BASE='http://127.0.0.1:5055'
def post(path,data):
    return json.load(urllib.request.urlopen(urllib.request.Request(BASE+path,data=json.dumps(data).encode(),headers={'Content-Type':'application/json'}),timeout=15))
for path in ['/','/receiver','/vpn-server','/style.css']:
    assert urllib.request.urlopen(BASE+path).status==200
post('/api/action',{'action':'reset'})
post('/api/receiver/config',{'vpn':'127.0.0.2'})
s=post('/api/send',{'message':'Rejected by receiver configuration','address':'127.0.0.1:8000','vpn':'127.0.0.1:9090'})
assert not s['ok']
assert not json.load(urllib.request.urlopen(BASE+'/api/receiver'))['packets']
post('/api/receiver/config',{'vpn':'127.0.0.1'})
s=post('/api/send',{'message':'Three real windows — hello receiver!','address':'127.0.0.1:8000','vpn':'localhost:9090'})
assert s['ok'],s
assert s['tunnel']['server'][1]==9090
assert json.load(urllib.request.urlopen(BASE+'/api/receiver'))['packets'][0]['message']=='Three real windows — hello receiver!'
monitor=json.load(urllib.request.urlopen(BASE+'/api/server'))
assert any(e.get('encoded_hex') for e in monitor['events'])
assert any(e.get('destination',[None,None])[1]==8000 for e in monitor['events'])
print('PASS: three pages, actual selected VPN endpoint, receiver IP filtering, delivery and scrambled server payload')
post('/api/action',{'action':'reset'})
