# server/traffic_monitor.py
import threading
import time
import socket
from scapy.all import sniff, DNS, DNSRR, IP

class TrafficMonitor:
    def __init__(self, db_manager):
        self.db = db_manager
        self.dns_cache = {} # Maps IP -> (Domain, ExpiryTime)
        self.cache_ttl = 3600 # Cache DNS records for 1 hour
        self.lock = threading.Lock()
        self.running = False

    def start(self):
        self.running = True
        # Start DNS sniffer in the background
        threading.Thread(target=self._sniff_dns, daemon=True).start()
        # Start cache cleanup loop
        threading.Thread(target=self._cleanup_cache, daemon=True).start()
        print("Traffic Monitor & DNS Sniffer started.")

    def _sniff_dns(self):
        def process_dns(pkt):
            if not self.running: return
            # Check if it's a DNS Response (qr == 1)
            if pkt.haslayer(DNS) and pkt[DNS].qr == 1:
                for i in range(pkt[DNS].ancount):
                    rr = pkt[DNS].an[i]
                    if rr.type == 1: # A Record (IPv4)
                        try:
                            domain = rr.rrname.decode('utf-8').rstrip('.')
                            ip = rr.rdata
                            with self.lock:
                                self.dns_cache[ip] = (domain, time.time() + self.cache_ttl)
                        except Exception:
                            pass
        try:
            # Sniff UDP port 53 for DNS responses
            sniff(filter="udp src port 53", prn=process_dns, store=0)
        except Exception as e:
            print(f"TrafficMonitor DNS Sniffer error: {e}")

    def _cleanup_cache(self):
        while self.running:
            time.sleep(60)
            now = time.time()
            with self.lock:
                expired = [ip for ip, (dom, exp) in self.dns_cache.items() if now > exp]
                for ip in expired:
                    del self.dns_cache[ip]

    def _is_ip(self, host):
        try:
            socket.inet_aton(host)
            return True
        except socket.error:
            return False

    def log_connection(self, username, src_ip, dst_ip_or_domain, dst_port):
        """Called by NAT Handler or Proxy Handler to log a new connection."""
        domain = None
        dst_ip = dst_ip_or_domain
        
        if self._is_ip(dst_ip_or_domain):
            # It's an IP, check our DNS cache to see if we know the domain
            with self.lock:
                if dst_ip in self.dns_cache:
                    domain = self.dns_cache[dst_ip][0]
        else:
            # It's already a domain (common in Proxy Mode)
            domain = dst_ip_or_domain
            dst_ip = "" 
        
        self.db.log_traffic(username, src_ip, dst_ip, dst_port, domain)