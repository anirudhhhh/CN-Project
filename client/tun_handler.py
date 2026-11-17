import os
import fcntl
import struct
import subprocess

# Linux ioctl constants for a TUN interface without packet-information headers
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

class TunInterface:
    def __init__(self, name="tun0", ip_addr="10.0.0.2/24"):
        self.name = name
        self.ip_addr = ip_addr
        self.fd = None
        self.server_ip = None

    def start(self, server_ip):
        self.server_ip = server_ip
        self.fd = os.open("/dev/net/tun", os.O_RDWR)
        ifr = struct.pack('16sH', self.name.encode('utf-8'), IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(self.fd, TUNSETIFF, ifr)
        
        try:
            subprocess.run(["ip", "addr", "add", self.ip_addr, "dev", self.name], check=True, stderr=subprocess.DEVNULL)
            subprocess.run(["ip", "link", "set", "dev", self.name, "up"], check=True, stderr=subprocess.DEVNULL)
            
            # --- ROUTING CONFIGURATION ---
            # 1. Find the default gateway
            gw_out = subprocess.check_output(["ip", "route", "show", "default"]).decode()
            if gw_out:
                default_gw = gw_out.split()[2]
                # 2. Add specific route for VPN server to avoid routing loop
                subprocess.run(["ip", "route", "add", self.server_ip, "via", default_gw], check=True, stderr=subprocess.DEVNULL)
            
            # 3. Redirect all other traffic to TUN (Overrides default route safely)
            subprocess.run(["ip", "route", "add", "0.0.0.0/1", "dev", self.name], check=True, stderr=subprocess.DEVNULL)
            subprocess.run(["ip", "route", "add", "128.0.0.0/1", "dev", self.name], check=True, stderr=subprocess.DEVNULL)
            
        except Exception as e:
            print(f"Error configuring TUN interface: {e}")

    def read(self, size=2048) -> bytes:
        import select
        if self.fd is not None:
            r, _, _ = select.select([self.fd], [], [], 1.0)
            if r:
                return os.read(self.fd, size)
        return b''

    def write(self, data: bytes):
        if self.fd is not None:
            os.write(self.fd, data)

    def close(self):
        try:
            # Cleanup routes on exit
            subprocess.run(["ip", "route", "del", "0.0.0.0/1", "dev", self.name], stderr=subprocess.DEVNULL)
            subprocess.run(["ip", "route", "del", "128.0.0.0/1", "dev", self.name], stderr=subprocess.DEVNULL)
            if self.server_ip:
                subprocess.run(["ip", "route", "del", self.server_ip], stderr=subprocess.DEVNULL)
        except:
            pass
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None