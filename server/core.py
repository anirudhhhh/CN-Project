# server/core.py
import socket
import threading
import time
from common.crypto import encrypt, decrypt
from common.protocol import unpack_header, pack_message, pack_data_messages, HEADER_SIZE, MSG_TYPE_DATA, MSG_TYPE_HEARTBEAT, MSG_TYPE_AUTH_REQ, MSG_TYPE_AUTH_RESP, FLAG_FRAGMENTED, FLAG_LAST_FRAGMENT
from server.nat_handler import NATHandler
from server.db_manager import DBManager
from server.rate_limiter import RateLimiter
from server.firewall import Firewall
from server.traffic_monitor import TrafficMonitor # NEW: Import Traffic Monitor

class VPNServerCore:
    def __init__(self, host='0.0.0.0', port=9090, *, enable_nat=True, db_path='vpn_database.db'):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.running = False
        self.client_send_locks = {}
        
        self.clients = {} 
        self.client_lock = threading.Lock()
        
        self.proxy_sessions = {}
        self.frag_buffers = {}
        
        self.db = DBManager(db_path)
        self.db.init_test_firewall_rules() 
        
        self.authenticated_clients = {} 
        self.client_usage = {} 
        
        self.rate_limiter = RateLimiter(rate_bytes_per_sec=1024 * 1024)
        self.firewall = Firewall(self.db) 
        
        self.traffic_monitor = TrafficMonitor(self.db) # NEW: Initialize Traffic Monitor
        
        # UPDATED: Pass traffic_monitor to NATHandler
        self.nat_handler = NATHandler(send_callback=self.send_to_client, traffic_monitor=self.traffic_monitor) if enable_nat else None

    def _observe(self, stage, **details):
        observer = getattr(self, 'trace_callback', None)
        if observer:
            observer(stage, details)

    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(10)
        self.running = True
        print(f"VPN Server listening on {self.host}:{self.port}")
        
        if self.nat_handler:
            self.traffic_monitor.start()
            self.nat_handler.start()
        threading.Thread(target=self._accept_loop, daemon=True).start()
        threading.Thread(target=self._accounting_loop, daemon=True).start()

    def _accept_loop(self):
        while self.running:
            try:
                client_sock, addr = self.server_socket.accept()
                with self.client_lock:
                    self.clients[addr] = client_sock
                    self.client_send_locks[addr] = threading.Lock()
                threading.Thread(target=self._handle_client, args=(client_sock, addr), daemon=True).start()
            except Exception:
                break

    def _handle_client(self, client_sock, addr):
        authenticated = False
        username = None
        
        while self.running:
            try:
                header = b''
                while len(header) < HEADER_SIZE:
                    chunk = client_sock.recv(HEADER_SIZE - len(header))
                    if not chunk: raise ConnectionError("Client disconnected")
                    header += chunk
                
                msg_type, session_id, flags, length = unpack_header(header)
                
                if authenticated and username:
                    self.rate_limiter.wait(username, 'up', length)
                
                payload = b''
                while len(payload) < length:
                    chunk = client_sock.recv(length - len(payload))
                    if not chunk: raise ConnectionError("Client disconnected")
                    payload += chunk
                    
                if authenticated and addr in self.client_usage:
                    self.client_usage[addr]['up'] += HEADER_SIZE + length
                    
                if flags & FLAG_FRAGMENTED:
                    frag_key = (addr, session_id)
                    if frag_key not in self.frag_buffers:
                        self.frag_buffers[frag_key] = b''
                    self.frag_buffers[frag_key] += payload
                    if flags & FLAG_LAST_FRAGMENT:
                        payload = self.frag_buffers.pop(frag_key)
                    else:
                        continue 
                
                decrypted_packet = decrypt(payload)
                
                if not authenticated:
                    if msg_type == MSG_TYPE_AUTH_REQ:
                        try:
                            user, pwd = decrypted_packet.decode('utf-8').split('\n')
                            if self.db.verify_user(user, pwd):
                                if self.db.check_quota(user):
                                    authenticated = True
                                    username = user
                                    db_session_id = self.db.create_session(username)
                                    
                                    with self.client_lock:
                                        self.authenticated_clients[addr] = username
                                        self.client_usage[addr] = {
                                            'session_id': db_session_id,
                                            'username': username,
                                            'up': 0, 'down': 0,
                                            'last_up': 0, 'last_down': 0
                                        }
                                        
                                    resp = b'SUCCESS'
                                    print(f"[+] User '{username}' authenticated from {addr}")
                                else:
                                    resp = b'QUOTA_EXHAUSTED'
                            else:
                                resp = b'INVALID_CREDENTIALS'
                        except Exception:
                            resp = b'BAD_FORMAT'
                            
                        lock = self.client_send_locks.get(addr)
                        if lock:
                            with lock:
                                framed_resp = pack_message(MSG_TYPE_AUTH_RESP, 0, 0, encrypt(resp))
                                if authenticated and addr in self.client_usage:
                                    self.client_usage[addr]['down'] += len(framed_resp)
                                client_sock.sendall(framed_resp)
                        
                        if not authenticated:
                            print(f"[-] Auth failed for {addr}: {resp.decode()}")
                            break 
                        continue 
                    else:
                        print(f"[-] Unauthenticated packet from {addr}. Dropping.")
                        break 

                if msg_type == MSG_TYPE_DATA:
                    if session_id == 0:
                        if not self.firewall.check_packet(username, decrypted_packet):
                            print(f"[*] Firewall BLOCKED TUN packet from {username}")
                            continue 
                            
                        # UPDATED: Pass username to NAT handler
                        if self.nat_handler:
                            self.nat_handler.process_outgoing(decrypted_packet, addr, username)
                    else:
                        if not self.firewall.check_app_layer(username, decrypted_packet):
                            print(f"[*] Firewall BLOCKED Proxy data from {username}")
                            continue 
                            
                        with self.client_lock:
                            target_sock = self.proxy_sessions.get((addr, session_id))
                        if target_sock:
                            try:
                                self._observe('decoded', session=session_id, tunnel_peer=list(addr), encoded_hex=payload.hex(' '), decoded_text=decrypted_packet.decode('utf-8', errors='replace'), bytes=len(decrypted_packet))
                                target_sock.sendall(decrypted_packet)
                                self._observe('forwarded', session=session_id, outbound_local=list(target_sock.getsockname()), destination=list(target_sock.getpeername()), bytes=len(decrypted_packet))
                            except: pass
                elif msg_type == 3: 
                    host_len = decrypted_packet[0]
                    host = decrypted_packet[1:1+host_len].decode()
                    port = int.from_bytes(decrypted_packet[1+host_len:1+host_len+2], 'big')
                    
                    if not self.firewall.check_proxy_connect(username, host, port):
                        self._observe('blocked', session=session_id, destination=f'{host}:{port}', tunnel_peer=list(addr))
                        print(f"[*] Firewall BLOCKED Proxy connection to {host}:{port} from {username}")
                        continue 
                    
                    # NEW: Log Proxy Connection
                    self.traffic_monitor.log_connection(username, addr[0], host, port)
                    
                    target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    try:
                        target_sock.settimeout(5.0)
                        target_sock.connect((host, port))
                        target_sock.settimeout(None)
                        self._observe('outbound_connected', session=session_id, tunnel_peer=list(addr), tunnel_listener=list(client_sock.getsockname()), outbound_local=list(target_sock.getsockname()), destination=list(target_sock.getpeername()))
                        with self.client_lock:
                            self.proxy_sessions[(addr, session_id)] = target_sock
                        threading.Thread(target=self._proxy_read_loop, args=(client_sock, target_sock, addr, session_id), daemon=True).start()
                    except Exception as e:
                        print(f"[-] Proxy connection failed to {host}:{port}")
                elif msg_type == MSG_TYPE_HEARTBEAT:
                    framed = pack_message(MSG_TYPE_HEARTBEAT, 0, 0, b'PONG')
                    lock = self.client_send_locks.get(addr)
                    if lock:
                        with lock:
                            if addr in self.client_usage:
                                self.client_usage[addr]['down'] += len(framed)
                            client_sock.sendall(framed)

            except Exception as e:
                print(f"[-] Client disconnected: {addr} ({e})")
                break
                
        self._disconnect_client(client_sock, addr)

    def _proxy_read_loop(self, client_sock, target_sock, addr, session_id):
        try:
            while self.running:
                data = target_sock.recv(4096)
                if not data:
                    break
                encrypted = encrypt(data)
                frames = pack_data_messages(session_id, encrypted)
                
                username = self.authenticated_clients.get(addr)
                if username:
                    total_len = sum(len(f) for f in frames)
                    self.rate_limiter.wait(username, 'down', total_len)
                
                lock = self.client_send_locks.get(addr)
                if lock:
                    with lock:
                        for frame in frames:
                            if addr in self.client_usage:
                                self.client_usage[addr]['down'] += len(frame)
                            try: client_sock.sendall(frame)
                            except: pass
        except Exception:
            pass
        finally:
            with self.client_lock:
                if (addr, session_id) in self.proxy_sessions:
                    del self.proxy_sessions[(addr, session_id)]
            try: target_sock.close()
            except: pass

    def send_to_client(self, addr, packet, session_id=0):
        with self.client_lock:
            client_sock = self.clients.get(addr)
            
        if client_sock:
            try:
                encrypted = encrypt(packet)
                frames = pack_data_messages(session_id, encrypted)
                
                username = self.authenticated_clients.get(addr)
                if username:
                    total_len = sum(len(f) for f in frames)
                    self.rate_limiter.wait(username, 'down', total_len)
                
                lock = self.client_send_locks.get(addr)
                if lock:
                    with lock:
                        for frame in frames:
                            if addr in self.client_usage:
                                self.client_usage[addr]['down'] += len(frame)
                            client_sock.sendall(frame)
            except Exception:
                self._disconnect_client(client_sock, addr)

    def _accounting_loop(self):
        while self.running:
            time.sleep(10) 
            
            with self.client_lock:
                active_addrs = list(self.client_usage.keys())
                
            for addr in active_addrs:
                # Safely calculate the difference using the lock
                with self.client_lock:
                    usage = self.client_usage.get(addr)
                    if not usage: continue
                    
                    up_diff = usage['up'] - usage['last_up']
                    down_diff = usage['down'] - usage['last_down']
                    
                    usage['last_up'] = usage['up']
                    usage['last_down'] = usage['down']
                
                # Sync to DB outside the lock to prevent freezing the server
                if up_diff > 0 or down_diff > 0:
                    has_quota = self.db.sync_usage(usage['username'], usage['session_id'], up_diff, down_diff)
                    
                    if not has_quota:
                        print(f"[*] Quota exhausted for user '{usage['username']}'. Disconnecting.")
                        client_sock = self.clients.get(addr)
                        if client_sock:
                            self._disconnect_client(client_sock, addr)

    def _disconnect_client(self, client_sock, addr):
        with self.client_lock:
            if addr in self.clients:
                del self.clients[addr]
            if addr in self.client_send_locks:
                del self.client_send_locks[addr]
            if addr in self.authenticated_clients:
                del self.authenticated_clients[addr]
                
            if addr in self.client_usage:
                usage = self.client_usage.pop(addr)
                up_diff = usage['up'] - usage['last_up']
                down_diff = usage['down'] - usage['last_down']
                self.db.sync_usage(usage['username'], usage['session_id'], up_diff, down_diff)
                self.db.close_session(usage['session_id'])
                
            to_remove = [k for k in self.proxy_sessions if k[0] == addr]
            for k in to_remove:
                try: self.proxy_sessions[k].close()
                except: pass
                del self.proxy_sessions[k]
                
        try:
            client_sock.close()
        except: pass
        
        if self.nat_handler:
            self.nat_handler.cleanup_client(addr)

    def kick_user(self, username):
        """Forcefully disconnects a user by username (Called by Admin Web Panel)."""
        target_addr = None
        with self.client_lock:
            for addr, user in self.authenticated_clients.items():
                if user == username:
                    target_addr = addr
                    break
                    
        if target_addr:
            print(f"[*] Admin kicked user '{username}'. Closing socket.")
            client_sock = self.clients.get(target_addr)
            if client_sock:
                self._disconnect_client(client_sock, target_addr)
            return True
        return False