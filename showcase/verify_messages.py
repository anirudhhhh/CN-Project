import json
import urllib.request
BASE='http://127.0.0.1:5055'
def post(path,data):
    req=urllib.request.Request(BASE+path,data=json.dumps(data).encode(),headers={'Content-Type':'application/json'})
    return json.load(urllib.request.urlopen(req,timeout=20))
post('/api/action',{'action':'reset'})
text='Hello audience — actual message! नमस्ते 🔐\nSecond line.'
r=post('/api/send',{'address':'127.0.0.1:8000','message':text})
assert r['ok'],r
assert r['receipt']['message']==text
outbound=next(e for e in r['vpn'] if e['stage']=='outbound_connected')
assert r['receipt']['peer']==':'.join(map(str,outbound['outbound_local']))
assert any(e['stage']=='forwarded' for e in r['vpn'])
server_plain=''.join(e['decoded_text'] for e in r['vpn'] if e['stage']=='decoded')
assert json.loads(server_plain.split('\r\n\r\n',1)[1])['message']==text
print('PASS: receiver observed the VPN server socket; server decoded and forwarded exact message')
wire=b''.join(bytes.fromhex(w['encoded_hex']) for w in r['wire'])
plain=bytes((b-3)%256 for b in wire)
assert json.loads(plain.split(b'\r\n\r\n', 1)[1])['message'] == text
inbox=json.load(urllib.request.urlopen('http://127.0.0.1:8000/inbox'))
assert inbox[0]['message']==text and inbox[0]['id']==r['id']
print('PASS: Unicode message, actual encoding trace, and independent receiver inbox')
post('/api/action',{'action':'block'})
r=post('/api/send',{'address':'127.0.0.1:8000','message':'This must not arrive'})
assert not r['ok']
assert len(json.load(urllib.request.urlopen('http://127.0.0.1:8000/inbox')))==1
print('PASS: blocked message never reaches receiver')
post('/api/action',{'action':'unblock'})
r=post('/api/send',{'address':'http://localhost:8000/message','message':'A'*10000})
assert r['ok'] and r['receipt']['message']=='A'*10000
print('PASS: hostname addressing, restored access and large fragmented message')
post('/api/action',{'action':'reset'})
print('Reset and ready.')
