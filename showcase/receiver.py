"""A real HTTP message receiver. Run on another machine with --host 0.0.0.0."""
import argparse
import json
import time
import socket
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

inbox = deque(maxlen=50)

class Receiver(BaseHTTPRequestHandler):
    allowed_vpn = None

    def do_POST(self):
        try:
            if Receiver.allowed_vpn and self.client_address[0] not in Receiver.allowed_vpn:
                self.reply(403, {'error': 'Packet rejected: sender is not the configured VPN server'})
                return
            length = int(self.headers.get('Content-Length', 0))
            if not 0 < length <= 100000:
                raise ValueError('Message must be between 1 and 100000 bytes')
            data = json.loads(self.rfile.read(length))
            text = data.get('message')
            if not isinstance(text, str) or not text.strip():
                raise ValueError('Enter a message')
            record = {'id': data.get('id'), 'message': text, 'time': time.strftime('%H:%M:%S'),
                      'peer': f'{self.client_address[0]}:{self.client_address[1]}',
                      'receiver': f'{self.server.server_address[0]}:{self.server.server_port}'}
            inbox.appendleft(record)
            print(f"RECEIVED from {record['peer']}: {text}", flush=True)
            self.reply(200, record)
        except Exception as exc:
            self.reply(400, {'error': str(exc)})

    def do_GET(self):
        if self.path == '/inbox':
            self.reply(200, list(inbox))
        else:
            body = b'''<!doctype html><meta charset="utf-8"><title>Receiver inbox</title><style>body{background:#111411;color:#f0eee4;font:20px system-ui;max-width:900px;margin:60px auto;padding:25px}article{padding:25px;border:1px solid #46513f;margin:20px 0;white-space:pre-wrap}small{color:#b9db92}</style><h1>Receiver inbox</h1><p>Messages actually accepted by this HTTP receiver.</p><div id="inbox"></div><script>async function load(){const r=await fetch('/inbox');const rows=await r.json();const box=document.querySelector('#inbox');box.replaceChildren();for(const row of rows){let a=document.createElement('article'),s=document.createElement('small'),p=document.createElement('p');s.textContent=row.time+' / from '+row.peer;p.textContent=row.message;a.append(s,p);box.append(a)}if(!rows.length)box.textContent='Waiting for a message...'}load();setInterval(load,1000)</script>'''
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def reply(self, status, data):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8000)
    args = parser.parse_args()
    print(f'Receiver listening on {args.host}:{args.port}', flush=True)
    ThreadingHTTPServer((args.host, args.port), Receiver).serve_forever()
