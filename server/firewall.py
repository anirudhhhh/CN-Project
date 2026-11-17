# server/firewall.py
import re
import socket
from scapy.all import IP, TCP, UDP, DNS, DNSQR

class Firewall:
    def __init__(self, db_manager):
        self.db = db_manager

    def get_rules(self, username):
        """Fetches rules applicable to this user (and global rules)."""
        with self.db.get_conn() as conn:
            cursor = conn.execute('''
                SELECT target_ip, target_port, target_domain, action 
                FROM firewall_rules 
                WHERE user_id IS NULL OR user_id = (SELECT id FROM users WHERE username = ?)
            ''', (username,))
            return cursor.fetchall()

    def is_blocked(self, username, ip=None, port=None, domain=None, payload=None):
        rules = self.get_rules(username)
        
        # ADVANCED: App-Layer Filtering (Extract domain from HTTP Host header)
        if payload:
            match = re.search(b"Host: (.*?)\\r\\n", payload, re.IGNORECASE)
            if match:
                extracted_domain = match.group(1).decode('utf-8').split(':')[0].strip()
                if not domain:
                    domain = extracted_domain

        for target_ip, target_port, target_domain, action in rules:
            match = False
            
            # Basic Filtering
            if target_ip and ip == target_ip:
                match = True
            if target_port and port == target_port:
                match = True
                
            # Advanced Filtering (Domain)
            if target_domain and domain:
                # Check if target_domain is a substring (e.g., 'example.com' blocks 'www.example.com')
                if target_domain.lower() in domain.lower():
                    match = True

            if match:
                return action == 'BLOCK'
        
        return False # Default ALLOW

    def check_proxy_connect(self, username, host, port):
        ip = host if self._is_ip(host) else None
        domain = host if not ip else None
        if self.is_blocked(username, ip=ip, port=port, domain=domain):
            self.db.log_firewall_block(username, ip, port, domain) # LOG IT
            return False
        return True

    def check_packet(self, username, raw_packet):
        try:
            pkt = IP(raw_packet)
            if not pkt.haslayer(IP): return True

            dst_ip = pkt.dst
            dst_port = None
            domain = None
            payload = None

            if pkt.haslayer(TCP):
                dst_port = pkt[TCP].dport
                payload = bytes(pkt[TCP].payload)
            elif pkt.haslayer(UDP):
                dst_port = pkt[UDP].dport
                payload = bytes(pkt[UDP].payload)
                if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                    domain = pkt[DNSQR].qname.decode('utf-8').rstrip('.')

            if self.is_blocked(username, ip=dst_ip, port=dst_port, domain=domain, payload=payload):
                self.db.log_firewall_block(username, dst_ip, dst_port, domain) # LOG IT
                return False 
            return True
        except Exception:
            return True 

    def check_app_layer(self, username, payload):
        if self.is_blocked(username, payload=payload):
            self.db.log_firewall_block(username, None, None, "App-Layer Block") # LOG IT
            return False
        return True

    def _is_ip(self, host):
        try:
            socket.inet_aton(host)
            return True
        except socket.error:
            return False