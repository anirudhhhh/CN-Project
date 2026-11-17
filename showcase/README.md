# Three-computer live showcase

A real message is sent through the project's SOCKS5 client and custom TCP tunnel. Three computers run separate roles and show separate windows. No simulated delivery, public cloud, TUN interface, sudo, or IP forwarding is needed for this proxy-mode showcase.

## 1. Network layout

Connect the three computers to the same reachable LAN or Wi-Fi. These are example addresses: replace them with your own.

| Computer | Role | Example LAN IP | Listening service |
| --- | --- | --- | --- |
| A | Sender | 192.168.1.10 | Local SOCKS5 proxy on 127.0.0.1:1080 |
| B | VPN server | 192.168.1.20 | Custom TCP tunnel on port 9090 |
| C | Receiver | 192.168.1.30 | HTTP message receiver on port 8000 |

Each computer also runs its own presentation page on port 5055.

```text
A: browser → Python sender → localhost SOCKS5 :1080
                               │
                               │ Custom framed TCP, scrambled payload
                               ▼
                         B: VPN server :9090
                               │ Decode, check policy, forward
                               │ HTTP over a new TCP connection
                               ▼
                         C: receiver :8000 → received packet window
```

`127.0.0.1` means the computer you are currently on. `0.0.0.0` means listen on all local IPv4 interfaces; never enter it as a destination. Find the active LAN IPv4 address in your network settings; `ipconfig` on Windows or `ip addr` on Linux also shows it. Use the address on the shared LAN, not a virtual adapter.

## 2. Install on ALL three computers

Copy the complete `real-public-network` source folder to each computer. Exclude `.showcase-venv`, `__pycache__` and generated databases; create a fresh environment on each machine. Keep `client/`, `common/`, `server/` and `showcase/` together.

Use Python 3.12+. From the project root on macOS/Linux:

```bash
python3 -m venv .showcase-venv
source .showcase-venv/bin/activate
python -m pip install -r showcase/requirements.txt
```

On Windows PowerShell:

```powershell
py -3 -m venv .showcase-venv
.\.showcase-venv\Scripts\python.exe -m pip install -r showcase\requirements.txt
```

The commands below use `python` in the activated environment. On Windows substitute `.\.showcase-venv\Scripts\python.exe` for `python`; activation is not required. On macOS/Linux you can likewise use `.showcase-venv/bin/python` explicitly. Dependencies are Flask and Scapy; CustomTkinter and PyJWT are not needed for these pages. Windows proxy mode avoids the Linux-only TUN import; Windows execution has not been verified in this session.

## 3. Computer B: start the VPN server FIRST

```bash
python showcase/app.py --role vpn --bind 0.0.0.0
```

On B open **http://127.0.0.1:5055/vpn-server**.

The actual tunnel listens on B's LAN IP, port **9090**. Its window displays source, destination, session and scrambled payload observed by the VPN server. A received message can span several chunks. Exact hexadecimal bytes are expandable.

Keep the terminal open. Use the built-in demo credentials `test` / `test`, which the sender supplies automatically. This uses an isolated `showcase/demo.sqlite3`, not the normal VPN database. The showcase clears demo firewall rules at server startup.

## 4. Computer C: start the receiver

```bash
python showcase/app.py --role receiver --bind 0.0.0.0
```

On C open **http://127.0.0.1:5055/receiver**.

In **My trusted VPN server IP**, enter B's actual LAN IP:

```text
192.168.1.20
```

Click **Apply VPN server**. This is required: the default only accepts localhost.

C accepts message connections on port **8000**. Its page shows accepted message packets and metadata, not a sender form or decoded VPN internals. The receiver's VPN setting enforces a source-IP allowlist. It does not establish a second tunnel or cryptographically authenticate B. In this LAN setup, B's outgoing source IP should be the configured address.

## 5. Computer A: start the sender

```bash
python showcase/app.py --role sender
```

On A open **http://127.0.0.1:5055/**.

Fill in:

| Field | Example value |
| --- | --- |
| My VPN server IP : port | 192.168.1.20:9090 |
| Receiver IP : port | 192.168.1.30:8000 |
| Message | Hello from computer A through computer B! |

Click **Send via my VPN server**. The selected VPN address is used for the actual client connection. The receiver must be running the HTTP receiver from this project; an arbitrary IP does not accept these messages automatically.

Expected result: A reports delivery, B shows scrambled incoming bytes with A as source and C as destination, and C displays the exact plaintext message. C's packet metadata shows B's IP as the sender, proving B forwarded the message.

The browser is the control window. Python on A opens the network sockets; opening A's page from another device would not move the sender process to that device.

## 6. Firewall and connectivity

Permit only the required inbound services on your private demo network:

| Machine | Inbound TCP port | Required from |
| --- | --- | --- |
| B / VPN | 9090 | A / sender |
| C / receiver | 8000 | B / VPN |
| B and C / browser console | 5055 | Only needed remotely if viewing their pages from another computer |

A does not need an inbound LAN port. Its SOCKS listener stays on loopback. Opening pages on each machine locally does not require remote access to port 5055. `--bind 0.0.0.0` also exposes the presentation console to the LAN; use a trusted lab network. These demo controls are not a production administration service.

On Windows, allow Python on the Private network when prompted, or create narrowly scoped inbound TCP rules. Avoid disabling the entire firewall. Some college/guest Wi-Fi networks isolate devices even when they share an SSID; use an approved LAN or hotspot that permits device-to-device traffic.

Optional checks: from A, `Test-NetConnection 192.168.1.20 -Port 9090` in PowerShell or `nc -vz 192.168.1.20 9090` on macOS/Linux. From B test C's port 8000 similarly. Ping alone does not prove the TCP service is reachable.

## 7. Presentation script

1. Put A's sender window, B's VPN window, and C's receiver window on the respective screens.
2. Point out the three real LAN IPs and configure B's IP on A and C.
3. Ask the audience for an unexpected message and type it on A.
4. Send it. Show the scrambled payload on B, then the exact message on C.
5. Point at C's observed sender: it is B, not A. Match it with B's outgoing connection metadata or captured network traffic.
6. Change C's trusted VPN IP to an unused address, such as `192.0.2.1`, and apply it. Send another message; it must fail and not appear on C.
7. Restore B's correct IP, apply it, and send successfully again.
8. Optional: capture B's LAN interface in Wireshark with `tcp.port == 9090 || tcp.port == 8000`. This separates incoming tunnel traffic from outgoing HTTP traffic. Do not claim a TCP segment equals one application frame.

The visible scrambled bytes include encoded HTTP headers and JSON, not just the text string. The project uses a reversible +3 byte shift, not secure cryptography. B decodes the payload, then forwards plaintext HTTP to C. This is a proxy tunnel demonstration, not an end-to-end encrypted messenger or full-device VPN.

## 8. Troubleshooting

| Symptom | Check |
| --- | --- |
| Connection refused | Correct IP/port, correct role running, B/C launched with `--bind 0.0.0.0` |
| Timeout reaching VPN | B's port 9090 firewall rule, shared reachable LAN, no Wi-Fi client isolation |
| VPN receives traffic but C gets nothing | C's service on 8000, B-to-C connectivity, C's trusted VPN IP is B's LAN IP |
| Sender says receiver did not acknowledge | Receiver rejected source IP, wrong service/path, or incomplete response; inspect C's terminal |
| Address already in use | Stop an old showcase or original VPN/GUI process; don't run `all` and a separate role on the same default ports |
| Cannot import Flask or Scapy | Install into the same Python environment used to start the role |
| Windows mentions `fcntl` | Copy the updated client/core.py; TUN imports are now deferred until TUN mode is selected |
| Sender tries wrong saved address | Sender fields persist in browser local storage; update them |
| Other windows show nothing | Each window reads its own role's process. Open the sender on A, VPN window on B, receiver on C |

Stop a role with Ctrl+C. Receiver inbox is in memory and clears on restart. To restart a presentation cleanly, stop A, B, C, then start B, C, A and configure the receiver again.

## 9. One-computer rehearsal

```bash
python showcase/app.py
```

Open these three pages:

- Sender: http://127.0.0.1:5055/
- Receiver: http://127.0.0.1:5055/receiver
- VPN: http://127.0.0.1:5055/vpn-server

Use sender VPN `127.0.0.1:9090`, receiver `127.0.0.1:8000`, and receiver trusted VPN `127.0.0.1`. All-in-one mode binds localhost by default. It proves forwarding and encoding but not different host IPs.

## 10. Options and verification

```bash
python showcase/app.py --help
```

Options: `--role all|sender|vpn|receiver`, `--bind`, `--web-port` (5055), `--vpn-port` (9090), `--receiver-port` (8000). Changing a port requires matching page settings and firewall rules. Each page's navigation links are local to that role host; use the explicit computer addresses when opening other roles across the LAN.

Run `python showcase/verify_three_roles.py` with the normal showcase idle. It starts and tears down three independent processes on one test host using alternate ports, then verifies forwarding, actual server payload capture, source-address matching and receiver rejection. The local sender port 1080 must be free. This passed on macOS; it is not a physical three-computer LAN test.

Older `verify_messages.py` and `verify_windows.py` target a running default all-in-one instance. The standalone `receiver.py` remains a minimal HTTP receiver, but the receiver role above is recommended because it includes the configurable trusted VPN setting and dedicated page.
