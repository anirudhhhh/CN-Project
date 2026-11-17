"""Exercise the running showcase over HTTP and its actual TCP tunnel."""
import json
import time
import urllib.request
BASE = 'http://127.0.0.1:5055'
def state():
    return json.load(urllib.request.urlopen(BASE + '/api/state'))
def action(name):
    req = urllib.request.Request(BASE + '/api/action', data=json.dumps({'action': name}).encode(), headers={'Content-Type': 'application/json'})
    json.load(urllib.request.urlopen(req, timeout=15))
    time.sleep(.3)
    return state()
action('reset')
assert not action('bad_auth')['connected']
assert action('connect')['connected']
s=action('request'); assert s['result']['ok'] and s['result']['reached']; print('PASS: real proxied HTTP response')
s=action('large'); assert s['result']['ok'] and s['result']['bytes']==65536; print('PASS: 64 KB fragmented transfer')
action('block'); s=action('request'); assert not s['result']['ok'] and not s['result']['reached'] and s['firewall']; print('PASS: firewall prevents destination access')
action('unblock'); assert action('request')['result']['ok']; print('PASS: access restored')
action('kick'); assert not state()['connected']; assert not action('request')['result']['ok']; print('PASS: admin kick')
assert action('connect')['connected']; assert action('request')['result']['ok']; print('PASS: reconnect')
time.sleep(10.5); assert state()['user'][3]>0; print('PASS: persisted accounting')
action('reset'); print('Demo reset and ready.')
