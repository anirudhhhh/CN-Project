import socket
import threading

class LoadBalancer:
    def __init__(self, host='0.0.0.0', port=9000, backend_servers=None):
        self.host = host
        self.port = port
        # Default backends if none provided (e.g., 2 server instances)
        self.backend_servers = backend_servers or [('127.0.0.1', 9090), ('127.0.0.1', 9091)]
        self.current_server_index = 0
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.running = False
        self.lock = threading.Lock()

    def get_next_server(self):
        with self.lock:
            server = self.backend_servers[self.current_server_index]
            self.current_server_index = (self.current_server_index + 1) % len(self.backend_servers)
            return server

    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(10)
        self.running = True
        print(f"Load Balancer listening on {self.host}:{self.port}")
        
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self):
        while self.running:
            try:
                client_sock, addr = self.server_socket.accept()
                backend_server = self.get_next_server()
                print(f"[LB] Client {addr} connected. Routing to backend {backend_server}")
                threading.Thread(target=self._handle_client, args=(client_sock, backend_server), daemon=True).start()
            except Exception as e:
                if self.running:
                    print(f"[LB] Accept error: {e}")
                break

    def _handle_client(self, client_sock, backend_server):
        try:
            backend_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            backend_sock.settimeout(5.0)
            backend_sock.connect(backend_server)
            backend_sock.settimeout(None)
            
            # Start bidirectional forwarding
            t1 = threading.Thread(target=self._forward, args=(client_sock, backend_sock), daemon=True)
            t2 = threading.Thread(target=self._forward, args=(backend_sock, client_sock), daemon=True)
            
            t1.start()
            t2.start()
            
            t1.join()
            t2.join()
        except Exception as e:
            print(f"[LB] Connection to backend {backend_server} failed: {e}")
        finally:
            try: client_sock.close()
            except: pass
            try: backend_sock.close()
            except: pass

    def _forward(self, src_sock, dst_sock):
        try:
            while self.running:
                data = src_sock.recv(4096)
                if not data:
                    break
                dst_sock.sendall(data)
        except Exception:
            pass
        finally:
            try: src_sock.shutdown(socket.SHUT_RDWR)
            except: pass
            try: dst_sock.shutdown(socket.SHUT_RDWR)
            except: pass

    def stop(self):
        self.running = False
        try:
            self.server_socket.close()
        except: pass
        print("Load Balancer stopped.")

if __name__ == "__main__":
    lb = LoadBalancer()
    try:
        lb.start()
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        lb.stop()
