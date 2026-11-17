# server/nat_handler.py
import threading
import random
import socket
from scapy.all import IP, TCP, UDP, ICMP, sniff

class NATHandler:
    # Optional connection logging
    def __init__(self, send_callback, traffic_monitor=None):
        self.send_callback = send_callback
        self.traffic_monitor = traffic_monitor
        self.running = False
        
        self.port_map_incoming = {}
        self.port_map_outgoing = {}
        self.map_lock = threading.Lock()
        
        import os
        self.server_ip = os.environ.get("VPN_SERVER_IP") or self._get_default_ip()
        
        self.raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    def _get_default_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = "127.0.0.1"
        finally:
            s.close()
        return ip

    def start(self):
        self.running = True
        threading.Thread(target=self._sniff_incoming, daemon=True).start()
        print(f"NAT Handler started. Masquerading as {self.server_ip}")

    # Rewrite and forward a packet for an authenticated client
    def process_outgoing(self, raw_packet, client_addr, username=None):
        try:
            pkt = IP(raw_packet)
            if not pkt.haslayer(IP):
                return
            
            client_internal_ip = pkt.src
            protocol = pkt.proto
            
            # Extract transport ports for NAT mapping and logging
            if pkt.haslayer(TCP):
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                layer = TCP
            elif pkt.haslayer(UDP):
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                layer = UDP
            elif pkt.haslayer(ICMP) and pkt[ICMP].type == 8: 
                sport = pkt[ICMP].id
                dport = 0
                layer = ICMP
            else:
                return 
            
            mapping_key = (client_addr, sport, protocol)
            with self.map_lock:
                if mapping_key in self.port_map_outgoing:
                    mapped_port = self.port_map_outgoing[mapping_key]
                else:
                    mapped_port = random.randint(30000, 60000)
                    while (mapped_port, protocol) in self.port_map_incoming:
                        mapped_port = random.randint(30000, 60000)
                        
                    self.port_map_outgoing[mapping_key] = mapped_port
                    self.port_map_incoming[(mapped_port, protocol)] = (client_internal_ip, sport, client_addr)
                    
                    # Log newly created NAT mappings
                    if self.traffic_monitor and username:
                        self.traffic_monitor.log_connection(username, client_internal_ip, pkt.dst, dport)
            
            pkt.src = self.server_ip
            if layer in (TCP, UDP):
                pkt[layer].sport = mapped_port
            elif layer == ICMP:
                pkt[layer].id = mapped_port
            
            del pkt.chksum
            del pkt[layer].chksum
            
            rebuilt_pkt = bytes(pkt)
            self.raw_sock.sendto(rebuilt_pkt, (pkt.dst, 0))
            
        except Exception as e:
            print(f"Error processing outgoing NAT: {e}")

    # Receive translated replies and clean up disconnected clients
    def _sniff_incoming(self):
        filter_str = f"ip dst {self.server_ip} and (tcp or udp or icmp)"
        
        def packet_handler(pkt):
            if not self.running:
                return
            
            if not pkt.haslayer(IP):
                return
                
            protocol = pkt[IP].proto
            if pkt.haslayer(TCP):
                dport = pkt[TCP].dport
                layer = TCP
            elif pkt.haslayer(UDP):
                dport = pkt[UDP].dport
                layer = UDP
            elif pkt.haslayer(ICMP) and pkt[ICMP].type == 0: # Echo Reply
                dport = pkt[ICMP].id
                layer = ICMP
            else:
                return
                
            with self.map_lock:
                mapping = self.port_map_incoming.get((dport, protocol))
                
            if mapping:
                client_internal_ip, original_sport, client_addr = mapping
                
                pkt[IP].dst = client_internal_ip
                if layer in (TCP, UDP):
                    pkt[layer].dport = original_sport
                elif layer == ICMP:
                    pkt[layer].id = original_sport
                
                del pkt[IP].chksum
                del pkt[layer].chksum
                
                raw_bytes = bytes(pkt[IP])
                self.send_callback(client_addr, raw_bytes)

        sniff(filter=filter_str, prn=packet_handler, store=0)

    def cleanup_client(self, client_addr):
        with self.map_lock:
            to_remove_incoming = []
            to_remove_outgoing = []
            
            for (mapped_port, proto), (c_ip, c_port, c_addr) in self.port_map_incoming.items():
                if c_addr == client_addr:
                    to_remove_incoming.append((mapped_port, proto))
                    to_remove_outgoing.append((c_addr, c_port, proto))
                    
            for key in to_remove_incoming:
                del self.port_map_incoming[key]
            for key in to_remove_outgoing:
                del self.port_map_outgoing[key]