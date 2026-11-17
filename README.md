# Spiced Chai VPN

An educational Python networking project with a custom framed TCP tunnel, SOCKS5 proxy, firewall, rate limiting, usage accounting, and an interactive message showcase. The showcase sends actual messages through separate sender, VPN server and receiver processes.

## Start here: three-computer live showcase

The complete installation, network configuration, firewall ports, presentation script and troubleshooting are in **[showcase/README.md](showcase/README.md)**.

Example topology — replace these IPs with your actual LAN addresses:

```text
Computer A / sender        Computer B / VPN          Computer C / receiver
192.168.1.10       ──────→  192.168.1.20:9090 ─────→ 192.168.1.30:8000
              framed TCP, scrambled          plaintext HTTP
```

Copy the entire source project to all three computers. Use Python 3.12+ and install the showcase dependencies into a new environment on each computer:

```bash
python3 -m venv .showcase-venv
source .showcase-venv/bin/activate
python -m pip install -r showcase/requirements.txt
```

Windows PowerShell:

```powershell
py -3 -m venv .showcase-venv
.\.showcase-venv\Scripts\python.exe -m pip install -r showcase\requirements.txt
```

Run these commands from the project root using that environment's Python. On Windows replace `python` with `.\.showcase-venv\Scripts\python.exe`.

| Computer | Start command | Open locally |
| --- | --- | --- |
| B: VPN, first | `python showcase/app.py --role vpn --bind 0.0.0.0` | http://127.0.0.1:5055/vpn-server |
| C: receiver | `python showcase/app.py --role receiver --bind 0.0.0.0` | http://127.0.0.1:5055/receiver |
| A: sender | `python showcase/app.py --role sender` | http://127.0.0.1:5055/ |

On C set **My trusted VPN server IP** to B's IP (`192.168.1.20`) and click **Apply VPN server**. On A set **My VPN server** to `192.168.1.20:9090`, **Receiver** to `192.168.1.30:8000`, type a message and send.

B's window shows source, destination and scrambled payload. C shows the accepted plaintext packet and B's source address. A reports the receiver's exact-message acknowledgement. The sender's setting selects its real tunnel endpoint; the receiver's setting enforces a source-IP allowlist, not a second tunnel.

Allow inbound TCP **9090 on B** and **8000 on C**. All machines need LAN reachability. Port 5055 is each machine's web console; remote access to it is unnecessary when viewing locally. No sudo or IP forwarding is needed for the proxy showcase. `0.0.0.0` is a listen address, not an address to enter in the sender.

### One-computer rehearsal

```bash
python showcase/app.py
```

Open the sender, receiver and VPN URLs above on the same laptop. Use VPN `127.0.0.1:9090`, receiver `127.0.0.1:8000`, and trusted VPN IP `127.0.0.1`.

## Networking implementation

- **Framing:** a six-byte header containing type (1 byte), session ID (2), flags (1), and payload length (2), in network byte order. TCP is a byte stream; frames need not align with TCP segments.
- **Multiplexing:** session IDs distinguish logical proxy connections over the client–server TCP tunnel.
- **Fragmentation:** larger application payloads are split into at most 1,024-byte chunks and reassembled.
- **Proxy mode:** a local SOCKS5 listener forwards configured application traffic through the server. It does not redirect all device traffic.
- **Firewall:** server-side destination IP/port/domain checks and readable HTTP Host/DNS inspection where available. HTTPS payloads are not decrypted.
- **Accounting:** SQLite user/session usage with periodic synchronization and quota checks.
- **Rate limiting:** per-user, per-direction token buckets.
- **Observation:** optional client/server callbacks provide actual encoded payload and forwarding metadata for the showcase. They are not packet captures.

Application protocols run over TCP and IP. A physical LAN demonstration also lets you inspect link-layer frames in Wireshark. Blockchain and AI are not implemented.

## Original Linux TUN mode and admin portal

The original entry point remains separate from the showcase. It instantiates raw-socket NAT and therefore requires appropriate privileges and a Linux setup for the full TUN path.

```bash
python -m pip install -r requirements.txt
sudo sysctl -w net.ipv4.ip_forward=1
sudo /absolute/path/to/your/venv/bin/python run_server.py
```

The original admin portal is http://127.0.0.1:5000; the tunnel is port 9090. Launch the Tk client with `python client/gui.py`; Linux TUN mode requires elevated privileges, `/dev/net/tun`, the `ip` utility and careful routing configuration. Its GUI currently hardcodes the server as localhost. Use the showcase sender for configurable remote VPN addresses. Do not run the original server alongside the showcase VPN on the same port.

Default demo credentials: user `test` / `test`; original admin portal `admin` / `admin`. JWT applies to the original web portal; tunnel authentication uses its own credential handshake. The load-balancer module is separate and is not started automatically.

## Project structure

```text
client/                 VPN client, SOCKS5 handler, Tk GUI, Linux TUN support
common/                 Protocol framing and educational byte-shift encoding
server/                 VPN forwarding, raw NAT, firewall, database and accounting
server/web_app/         Original Flask admin/user portal
showcase/app.py         Role-based presentation launcher
showcase/index.html     Sender window
showcase/receiver.html  Receiver window
showcase/server.html    VPN server window
showcase/receiver.py    HTTP receiver implementation
showcase/README.md      Complete three-computer instructions
load_balancer/          Standalone TCP load balancer
run_server.py           Original privileged server entry point
```

## Verification and limits

`python showcase/verify_three_roles.py` checks three independent processes over real sockets on one host: selected tunnel endpoint, forwarding, server observation, receiver acknowledgement and source-IP rejection. Tested on macOS. A physical three-PC LAN and Windows runtime have not been tested in this session. See the showcase guide for rehearsal checks.

This is educational software. The +3 byte shift is reversible obfuscation, **not secure encryption**. The VPN server recovers plaintext and forwards HTTP to the receiver. Default credentials, a source-IP allowlist and a development web console do not provide production security. Use a trusted demo network and non-sensitive messages. The TUN path needs its own validation before presentation.
