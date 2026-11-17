# client/core.py
import socket
import threading
import time
from common.crypto import encrypt, decrypt
from common.protocol import unpack_header, pack_message, pack_data_messages, HEADER_SIZE, MSG_TYPE_DATA, MSG_TYPE_HEARTBEAT, MSG_TYPE_AUTH_REQ, MSG_TYPE_AUTH_RESP, FLAG_FRAGMENTED, FLAG_LAST_FRAGMENT
from client.proxy_handler import ProxyHandler

class VPNClientCore:
    def __init__(self, server_ip, server_port, mode="TUN", username="", password="", status_callback=None):
        self.server_ip = server_ip
        self.server_port = server_port
        self.mode = mode
        self.username = username
        self.password = password
        self.status_callback = status_callback
        
        self.sock = None
        self.running = False
        
        self.tun = None
        self.proxy = None
        self.send_lock = threading.Lock()
        self.frag_buffers = {}
        
    def _proxy_connect_requested(self, session_id, host, port):
        if self.running and self.sock:
            host_bytes = host.encode()
            payload = bytes([len(host_bytes)]) + host_bytes + port.to_bytes(2, 'big')
            encrypted = encrypt(payload)
            framed = pack_message(3, session_id, 0, encrypted)
            with self.send_lock:
                self.sock.sendall(framed)

    def start(self):
        self.running = True
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5.0) 
            self.sock.connect((self.server_ip, self.server_port))
            
            # --- AUTHENTICATION HANDSHAKE ---
            auth_payload = f"{self.username}\n{self.password}".encode('utf-8')
            enc_auth = encrypt(auth_payload)
            self.sock.sendall(pack_message(MSG_TYPE_AUTH_REQ, 0, 0, enc_auth))
            
            # Wait for Auth Response
            header = b''
            while len(header) < HEADER_SIZE:
                chunk = self.sock.recv(HEADER_SIZE - len(header))
                if not chunk: raise ConnectionError("Connection closed during auth")
                header += chunk
                
            msg_type, session_id, flags, length = unpack_header(header)
            payload = b''
            while len(payload) < length:
                chunk = self.sock.recv(length - len(payload))
                if not chunk: raise ConnectionError("Connection closed during auth")
                payload += chunk
                
            dec_payload = decrypt(payload)
            if msg_type != MSG_TYPE_AUTH_RESP or dec_payload != b'SUCCESS':
                raise Exception(f"Auth Failed: {dec_payload.decode('utf-8', errors='ignore')}")
            # --- END AUTHENTICATION ---

            self.sock.settimeout(None) 
            
            if self.status_callback:
                self.status_callback("Connected")
                
            if self.mode == "TUN":
                from client.tun_handler import TunInterface
                self.tun = TunInterface()
                self.tun.start(self.server_ip)
                threading.Thread(target=self._tun_read_loop, daemon=True).start()
            else:
                self.proxy = ProxyHandler(data_callback=self._proxy_data_received, connect_callback=self._proxy_connect_requested)
                self.proxy.start()
                
            threading.Thread(target=self._tcp_receive_loop, daemon=True).start()
            threading.Thread(target=self._heartbeat_loop, daemon=True).start()
            
        except Exception as e:
            self.running = False
            if self.status_callback:
                self.status_callback(f"Error: {e}")
            self.stop()

    def _tun_read_loop(self):
        while self.running and self.tun:
            try:
                packet = self.tun.read()
                if packet:
                    encrypted = encrypt(packet)
                    frames = pack_data_messages(0, encrypted)
                    with self.send_lock:
                        for frame in frames:
                            self.sock.sendall(frame)
            except Exception:
                break
        if self.tun:
            try: self.tun.close()
            except: pass

    def _proxy_data_received(self, session_id, data):
        if self.running and self.sock:
            try:
                encrypted = encrypt(data)
                trace = getattr(self, "trace_callback", None)
                if trace:
                    trace(session_id, data, encrypted)
                frames = pack_data_messages(session_id, encrypted)
                with self.send_lock:
                    for frame in frames:
                        self.sock.sendall(frame)
            except Exception:
                pass

    def _tcp_receive_loop(self):
        if self.sock:
            self.sock.settimeout(1.0)
        while self.running:
            try:
                header = b''
                while len(header) < HEADER_SIZE:
                    if not self.running: return
                    try:
                        chunk = self.sock.recv(HEADER_SIZE - len(header))
                        if not chunk: raise ConnectionError("Connection closed by server")
                        header += chunk
                    except socket.timeout:
                        continue
                
                msg_type, session_id, flags, length = unpack_header(header)
                
                payload = b''
                while len(payload) < length:
                    if not self.running: return
                    try:
                        chunk = self.sock.recv(length - len(payload))
                        if not chunk: raise ConnectionError("Connection closed by server")
                        payload += chunk
                    except socket.timeout:
                        continue
                        
                if flags & FLAG_FRAGMENTED:
                    if session_id not in self.frag_buffers:
                        self.frag_buffers[session_id] = b''
                    self.frag_buffers[session_id] += payload
                    if flags & FLAG_LAST_FRAGMENT:
                        payload = self.frag_buffers.pop(session_id)
                    else:
                        continue 
                    
                decrypted = decrypt(payload)
                
                if msg_type == MSG_TYPE_DATA:
                    if self.mode == "TUN" and self.tun:
                        self.tun.write(decrypted)
                    elif self.mode == "Proxy" and self.proxy:
                        self.proxy.write(session_id, decrypted)
                        
                elif msg_type == MSG_TYPE_HEARTBEAT:
                    pass
            except Exception as e:
                if self.running and self.status_callback:
                    self.status_callback(f"Connection lost: {e}")
                self.stop()
                break

    def _heartbeat_loop(self):
        while self.running:
            try:
                time.sleep(10) 
                if self.running and self.sock:
                    framed = pack_message(MSG_TYPE_HEARTBEAT, 0, 0, b'PING')
                    with self.send_lock:
                        self.sock.sendall(framed)
            except Exception:
                break

    def stop(self):
        self.running = False
        if self.sock:
            try: 
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
            except: pass
        if self.proxy:
            try: self.proxy.stop()
            except: pass