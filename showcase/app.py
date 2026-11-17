"""Local presentation console: real project sockets, isolated demo database."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import atexit
import json
import uuid
from urllib.parse import urlsplit
from receiver import Receiver, inbox
import socket
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from flask import Flask, jsonify, request, send_from_directory, redirect
from server.core import VPNServerCore
from client.core import VPNClientCore

ROOT = Path(__file__).resolve().parent
app = Flask(__name__)
events = deque(maxlen=100)
operation_lock = threading.Lock()
client = None
status = 'Disconnected'
hits = 0
last_result = None
last_message = None
wire_trace = deque(maxlen=30)
vpn_events = deque(maxlen=60)
core = None
role = 'all'
bind_host = '127.0.0.1'
vpn_port = 9090
receiver_port = 8000
receiver_vpn = '127.0.0.1'
Receiver.allowed_vpn = {'127.0.0.1'}


def event(kind, message):
    events.append({'time': time.strftime('%H:%M:%S'), 'kind': kind, 'message': message})


def callback(message):
    global status
    status = message
    event('connection', message)


class Destination(Receiver):
    def do_GET(self):
        if self.path == '/large':
            body = b'network-payload ' * 5000
            body = body[:65536]
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            super().do_GET()

    def do_POST(self):
        global hits
        before = len(inbox)
        super().do_POST()
        if len(inbox) > before or (inbox and len(inbox) == inbox.maxlen):
            hits += 1
            event('receiver', 'Receiver accepted a message via an actual HTTP connection')


def server_trace(stage, details):
    vpn_events.append({'stage': stage, 'time': time.strftime('%H:%M:%S'), **details})


def trace(session_id, plain, encoded):
    wire_trace.append({'session': session_id, 'plain_bytes': len(plain),
                       'encoded_hex': encoded.hex(' '),
                       'encoded_preview': ''.join(chr(b) if 32 <= b < 127 else '.' for b in encoded)})


def deliver(text, address, vpn_address='127.0.0.1:9090'):
    global client, last_message
    if not isinstance(text, str) or not text.strip() or len(text.encode()) > 16000:
        raise ValueError('Enter a message of up to 16000 UTF-8 bytes')
    target = urlsplit(address if '://' in address else 'http://' + address)
    if target.scheme != 'http' or not target.hostname or target.username or target.password:
        raise ValueError('Use the HTTP address of a running message receiver, e.g. 127.0.0.1:8000')
    host = target.hostname
    port = target.port or 8000
    if len(host.encode('idna')) > 255:
        raise ValueError('Receiver hostname is too long')
    vpn_target = urlsplit('tcp://' + vpn_address.replace('tcp://', ''))
    if not vpn_target.hostname:
        raise ValueError('Enter the VPN server IP and port')
    vpn_host, vpn_port = vpn_target.hostname, vpn_target.port or 9090
    started = time.monotonic()
    wire_trace.clear()
    vpn_events.clear()
    identifier = str(uuid.uuid4())
    last_message = {'id': identifier, 'sent': text, 'address': address, 'ok': False, 'receipt': None}
    try:
        if client and (client.server_ip != vpn_host or client.server_port != vpn_port):
            client.stop()
            time.sleep(.2)
        if not client or not client.running:
            client = VPNClientCore(vpn_host, vpn_port, mode='Proxy', username='test', password='test', status_callback=callback)
            client.trace_callback = trace
            client.start()
        client.trace_callback = trace
        body = json.dumps({'id': identifier, 'message': text}, ensure_ascii=False).encode()
        with socket.create_connection(('127.0.0.1', 1080), timeout=3) as sock:
            sock.settimeout(4)
            sock.sendall(b'\x05\x01\x00')
            if read_exact(sock, 2) != b'\x05\x00':
                raise ConnectionError('SOCKS handshake rejected')
            hostname = host.encode('idna')
            sock.sendall(b'\x05\x01\x00\x03' + bytes([len(hostname)]) + hostname + port.to_bytes(2, 'big'))
            read_exact(sock, 10)
            packet = (f'POST {target.path or "/message"} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode() + body
            sock.sendall(packet)
            stream = sock.makefile('rb')
            headline = stream.readline().decode().strip()
            headers = {}
            while True:
                line = stream.readline()
                if line in (b'\r\n', b''):
                    break
                k, v = line.decode().split(':', 1)
                headers[k.lower()] = v.strip()
            receipt = json.loads(stream.read(int(headers.get('content-length', 0))))
            if '200' not in headline or receipt.get('id') != identifier or receipt.get('message') != text:
                raise ConnectionError('Receiver did not acknowledge this exact message')
            last_message.update(ok=True, receipt=receipt)
            event('delivery', f'Receiver acknowledged message {identifier[:8]} · {len(text.encode())} UTF-8 bytes')
    except Exception as exc:
        last_message['error'] = str(exc)
        event('delivery', f'Delivery failed: {exc}')
    last_message.update(ms=round((time.monotonic()-started)*1000), wire=list(wire_trace), vpn=list(vpn_events), tunnel={'client': list(client.sock.getsockname()), 'server': list(client.sock.getpeername())} if client and client.sock and client.running else None)
    return last_message


def read_exact(sock, count):
    result = b''
    while len(result) < count:
        chunk = sock.recv(count-len(result))
        if not chunk:
            raise ConnectionError('Socket closed before response completed')
        result += chunk
    return result


def send_request(large=False):
    started = time.monotonic()
    before = hits
    try:
        with socket.create_connection(('127.0.0.1', 1080), timeout=2) as sock:
            sock.settimeout(2)
            sock.sendall(b'\x05\x01\x00')
            if read_exact(sock, 2) != b'\x05\x00':
                raise ConnectionError('SOCKS handshake rejected')
            sock.sendall(b'\x05\x01\x00\x01' + socket.inet_aton('127.0.0.1') + (8000).to_bytes(2, 'big'))
            read_exact(sock, 10)
            path = '/large' if large else '/'
            sock.sendall(f'GET {path} HTTP/1.1\r\nHost: 127.0.0.1:8000\r\nConnection: close\r\n\r\n'.encode())
            stream = sock.makefile('rb')
            headline = stream.readline().decode().strip()
            headers = {}
            while True:
                line = stream.readline()
                if line in (b'\r\n', b''):
                    break
                key, val = line.decode().split(':', 1)
                headers[key.lower()] = val.strip()
            length = int(headers.get('content-length', 0))
            body = stream.read(length)
            if len(body) != length or '200' not in headline:
                raise ConnectionError('Incomplete HTTP response')
        result = {'ok': True, 'title': headline, 'bytes': len(body), 'preview': body[:170].decode(), 'reached': hits > before}
    except Exception as exc:
        blocked = any(row[0] == 'test' and row[2] == 8000 for row in core.db.get_firewall_logs())
        result = {'ok': False, 'title': 'Blocked by firewall' if blocked and hits == before else 'Request failed', 'bytes': 0, 'preview': str(exc), 'reached': hits > before}
    result['ms'] = round((time.monotonic()-started)*1000)
    event('request', f"{result['title']} · {result['bytes']:,} bytes · {result['ms']} ms")
    return result


@app.before_request
def local_only():
    # Mutations accept same-origin JSON only, preventing cross-site form requests.
    if request.method == 'POST' and (not request.is_json or (request.headers.get('Origin') and request.headers['Origin'] != request.host_url.rstrip('/'))):
        return jsonify(error='Use the local showcase with JSON requests'), 403


@app.get('/')
def index():
    if role == 'receiver':
        return redirect('/receiver')
    if role == 'vpn':
        return redirect('/vpn-server')
    return send_from_directory(ROOT, 'index.html')


@app.get('/guide')
def guide():
    return send_from_directory(ROOT, 'README.md', mimetype='text/plain')


@app.get('/api/info')
def info():
    return jsonify(role=role)


@app.get('/style.css')
def stylesheet():
    return send_from_directory(ROOT, 'style.css')


@app.get('/receiver')
def receiver_window():
    return send_from_directory(ROOT, 'receiver.html')


@app.get('/api/receiver')
def receiver_state():
    return jsonify(vpn=receiver_vpn, address=f'{bind_host}:{receiver_port}', packets=list(inbox))


@app.post('/api/receiver/config')
def configure_receiver():
    global receiver_vpn
    value = (request.get_json() or {}).get('vpn', '').strip()
    try:
        host = urlsplit('tcp://' + value.replace('tcp://', '')).hostname
        if not host:
            raise ValueError('Enter the VPN server IP')
        addresses = {item[4][0] for item in socket.getaddrinfo(host, None, socket.AF_INET)}
    except (ValueError, OSError) as exc:
        return jsonify(error=str(exc)), 400
    receiver_vpn = value
    Receiver.allowed_vpn = addresses
    return jsonify(ok=True, vpn=value)


@app.get('/vpn-server')
def server_window():
    return send_from_directory(ROOT, 'server.html')


@app.get('/api/server')
def server_state():
    if core is None:
        return jsonify(listener=None, events=[], status='VPN server is not running in this role', listening=False, active_clients=0)
    with core.client_lock:
        active = len(core.authenticated_clients)
    return jsonify(listener=f'{bind_host}:{vpn_port}', events=list(vpn_events),
                   status=f'Listening / {active} authenticated client(s)' if core.running else 'Stopped',
                   listening=core.running, active_clients=active)


@app.get('/api/state')
def state():
    if core is None:
        return jsonify(error='This role has no local VPN server; use its dedicated window'), 404
    with core.client_lock:
        active = 'test' in core.authenticated_clients.values()
        up = sum(u['up'] for u in core.client_usage.values())
        down = sum(u['down'] for u in core.client_usage.values())
    rules = core.db.get_all_firewall_rules()
    return jsonify(connected=active, status=status, upload=up, download=down, hits=hits,
                   blocked=any(r[2] == 8000 and r[4] == 'BLOCK' for r in rules),
                   events=list(events)[::-1], traffic=core.db.get_traffic_logs(12),
                   firewall=core.db.get_firewall_logs(12), result=last_result,
                   user=core.db.get_user('test'), message=last_message, inbox=list(inbox))


@app.post('/api/send')
def send_message():
    if role not in ('sender', 'all'):
        return jsonify(error='Run the sender role to send messages'), 400
    with operation_lock:
        data = request.get_json() or {}
        try:
            return jsonify(deliver(data.get('message'), data.get('address', '127.0.0.1:8000'), data.get('vpn', '127.0.0.1:9090')))
        except (ValueError, TypeError) as exc:
            return jsonify(error=str(exc)), 400


@app.post('/api/action')
def action():
    global client, last_result, hits, last_message
    if core is None:
        return jsonify(error='Legacy demo controls require all-in-one mode'), 400
    with operation_lock:
        name = (request.get_json() or {}).get('action')
        if name in ('connect', 'bad_auth'):
            if client:
                client.stop()
                time.sleep(.15)
            client = VPNClientCore('127.0.0.1', 9090, mode='Proxy', username='test',
                                   password='wrong' if name == 'bad_auth' else 'test', status_callback=callback)
            client.trace_callback = trace
            client.start()
        elif name == 'request' or name == 'large':
            last_result = send_request(name == 'large')
        elif name == 'block':
            core.db.add_firewall_rule(target_port=8000, username='test')
            event('firewall', 'BLOCK rule added · user test · destination port 8000')
        elif name == 'unblock':
            for row in core.db.get_all_firewall_rules():
                if row[2] == 8000:
                    core.db.delete_firewall_rule(row[0])
            event('firewall', 'Port 8000 rule removed · new requests allowed')
        elif name == 'kick':
            core.kick_user('test')
            event('admin', 'Administrator terminated test user’s TCP tunnel')
        elif name == 'reset':
            if client:
                client.stop()
            time.sleep(.2)
            for row in core.db.get_all_firewall_rules():
                core.db.delete_firewall_rule(row[0])
            with core.db.get_conn() as conn:
                conn.execute('DELETE FROM firewall_logs')
                conn.execute('DELETE FROM traffic_logs')
                conn.execute("UPDATE users SET used_quota=0, status='ACTIVE' WHERE username='test'")
            events.clear()
            inbox.clear()
            wire_trace.clear()
            vpn_events.clear()
            last_message = None
            hits = 0
            callback('Disconnected')
            last_result = None
            event('system', 'Presentation reset · ready for a new connection')
        else:
            return jsonify(error='Unknown action'), 400
    return jsonify(ok=True)


def boot():
    global core
    if role in ('vpn', 'all'):
        core = VPNServerCore(host=bind_host, port=vpn_port, enable_nat=False,
                             db_path=str(ROOT / 'demo.sqlite3'))
        core.trace_callback = server_trace
        for row in core.db.get_all_firewall_rules():
            core.db.delete_firewall_rule(row[0])
        core.start()
        event('system', f'VPN tunnel listening on {bind_host}:{vpn_port}')
    if role in ('receiver', 'all'):
        destination = ThreadingHTTPServer((bind_host, receiver_port), Destination)
        threading.Thread(target=destination.serve_forever, daemon=True).start()
        atexit.register(destination.server_close)
        event('system', f'Receiver listening on {bind_host}:{receiver_port}')


def detect_lan_ip():
    """Ask the OS which local IPv4 address its default route uses; send no data."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(('8.8.8.8', 80))
            candidate = probe.getsockname()[0]
            if not candidate.startswith('127.'):
                return candidate
    except OSError:
        pass
    try:
        for item in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            candidate = item[4][0]
            if not candidate.startswith('127.') and candidate != '0.0.0.0':
                return candidate
    except OSError:
        pass
    return None


def startup_banner(selected_role, binding, web, tunnel, receiver, advertised=None):
    lan = advertised or (detect_lan_ip() if binding in ('0.0.0.0', '127.0.0.1', 'localhost') else binding)
    remote = binding not in ('127.0.0.1', 'localhost')
    local = '127.0.0.1' if binding == '0.0.0.0' else binding
    path = {'vpn': '/vpn-server', 'receiver': '/receiver'}.get(selected_role, '/')
    lines = ['\n' + '=' * 64, f'SPICED CHAI / {selected_role.upper()}',
             f'Open this window here: http://{local}:{web}{path}',
             f'Detected LAN IP: {lan or "unavailable; inspect network settings"}']
    if remote and lan:
        lines.append(f'Web page from another PC: http://{lan}:{web}{path}')
    if selected_role in ('vpn', 'all'):
        endpoint = f'{lan if remote and lan else local}:{tunnel}'
        lines += [f'VPN TUNNEL: {endpoint}',
                  f'  Sender field "My VPN server IP : port": {endpoint}',
                  f'  Receiver field "My trusted VPN server IP": {lan if remote and lan else local}']
    if selected_role in ('receiver', 'all'):
        endpoint = f'{lan if remote and lan else local}:{receiver}'
        lines += [f'MESSAGE RECEIVER: {endpoint}',
                  f'  Sender field "Receiver IP : port": {endpoint}',
                  "  In the receiver window, apply the VPN machine's IP (no port)."]
    if selected_role == 'sender':
        lines += ["Enter the VPN machine's printed TUNNEL address and the",
                  "receiver machine's printed MESSAGE RECEIVER address in this page."]
    if not remote:
        lines.append('Local-only listeners. For VPN/receiver LAN access use --bind 0.0.0.0.')
    elif not lan:
        lines.append('Set --advertise-ip YOUR_LAN_IP to print usable LAN endpoints.')
    else:
        lines.append('Multiple adapters? Verify this IP; override with --advertise-ip if needed.')
    lines += ['Web page ports are NOT message/tunnel ports.', '=' * 64 + '\n']
    return '\n'.join(lines)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Spiced Chai real three-computer message showcase')
    parser.add_argument('--role', choices=['all', 'sender', 'vpn', 'receiver'], default='all')
    parser.add_argument('--bind', default='127.0.0.1', help='Socket listener address; use 0.0.0.0 for LAN showcase')
    parser.add_argument('--web-port', type=int, default=5055)
    parser.add_argument('--vpn-port', type=int, default=9090)
    parser.add_argument('--receiver-port', type=int, default=8000)
    parser.add_argument('--advertise-ip', help='LAN IPv4 to print when automatic detection chooses the wrong adapter')
    args = parser.parse_args()
    role, bind_host, vpn_port, receiver_port = args.role, args.bind, args.vpn_port, args.receiver_port
    boot()
    print(startup_banner(role, bind_host, args.web_port, vpn_port, receiver_port, args.advertise_ip), flush=True)
    app.run(host=bind_host, port=args.web_port, threaded=True, use_reloader=False)
