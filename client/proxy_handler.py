import socket
import threading

class ProxyHandler:
    def __init__(self, host='127.0.0.1', port=1080, data_callback=None, connect_callback=None):
        self.host = host
        self.port = port
        self.data_callback = data_callback
        self.connect_callback = connect_callback
        self.server_socket = None
        self.running = False
        self.clients = {}  # session_id -> client socket

    def start(self):
        """Starts the local SOCKS5 proxy listener."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(10)
        self.server_socket.settimeout(1.0)
        self.running = True
        
        threading.Thread(target=self._accept_loop, daemon=True).start()
        print(f"Proxy handler listening on {self.host}:{self.port}")

    def _accept_loop(self):
        while self.running:
            try:
                client_sock, addr = self.server_socket.accept()
                session_id = id(client_sock) % 65535
                self.clients[session_id] = client_sock
                threading.Thread(target=self._handle_client, args=(session_id, client_sock), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break
        
        if self.server_socket:
            try: self.server_socket.close()
            except: pass

    def _handle_client(self, session_id, client_sock):
        try:
            # Minimal SOCKS5 handshake
            version_methods = client_sock.recv(262)
            if version_methods and version_methods[0] == 5:
                client_sock.sendall(b'\x05\x00') # NO AUTH
                request = client_sock.recv(4096)
                if request and request[0] == 5 and request[1] == 1: # CONNECT
                    atyp = request[3]
                    host = ""
                    if atyp == 1: # IPv4
                        host = socket.inet_ntoa(request[4:8])
                        port = int.from_bytes(request[8:10], 'big')
                    elif atyp == 3: # Domain
                        domain_len = request[4]
                        host = request[5:5+domain_len].decode()
                        port = int.from_bytes(request[5+domain_len:5+domain_len+2], 'big')
                    
                    if host and self.connect_callback:
                        # Tell VPN Core to establish connection to this host:port
                        self.connect_callback(session_id, host, port)
                        # Reply success (bind address dummy)
                        client_sock.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
                    
            # After handshake, forward data
            while self.running:
                data = client_sock.recv(4096)
                if not data:
                    break
                if self.data_callback:
                    self.data_callback(session_id, data)
        except Exception as e:
            pass
        finally:
            self._close_client(session_id)

    def write(self, session_id, data):
        """Write decrypted data back to the proxy client."""
        if session_id in self.clients:
            try:
                self.clients[session_id].sendall(data)
            except Exception:
                self._close_client(session_id)

    def _close_client(self, session_id):
        if session_id in self.clients:
            try:
                self.clients[session_id].close()
            except:
                pass
            del self.clients[session_id]

    def stop(self):
        """Stops the proxy server and disconnects clients."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        for session_id in list(self.clients.keys()):
            self._close_client(session_id)
