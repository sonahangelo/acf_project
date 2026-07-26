## Setup: avoiding sudo for capture

Packet capture requires raw socket access. Rather than granting this to the
system-wide Python interpreter (which would let *any* script use raw
sockets), we use a dedicated copy of Python just for ACF:

```bash
cp /usr/bin/python3.11 acf-env/bin/python3-acf
sudo setcap cap_net_raw,cap_net_admin=eip acf-env/bin/python3-acf
```

Then run ACF commands with `acf-env/bin/python3-acf` instead of `python3`
for capture/learn/detect modes:

```bash
acf-env/bin/python3-acf main.py --mode learn --count 5000
acf-env/bin/python3-acf main.py --mode detect
```

Other commands (training, status, blocklist, feedback, dashboard) don't
need raw socket access and can keep using the regular `python3`.

Note: `python3-acf` is a real copy, not a symlink, and won't survive a venv
recreation -- redo the `cp` + `setcap` steps if you rebuild the venv.

Save, exit.

**Step 2 — Add `python3-acf` to `.gitignore`** (it's a binary copy, shouldn't be committed):
```bash
echo "acf-env/bin/python3-acf" >> .gitignore
```

**Step 3 — Commit:**
```bash
git add .
git commit -m "Narrow setcap grant: use a dedicated python3-acf binary instead of the system-wide interpreter, confining raw-socket capability to just ACF"
```

Paste the confirmation — that closes out #4 and completes everything from your original list.


Note: this must be re-applied if the Python venv or system Python version
changes (e.g. after `apt upgrade` or recreating the venv), since capabilities
are stored on the specific binary file, not carried over automatically.

Live enforcement (`dry_run: false`) still requires `sudo` for the actual
`iptables` calls -- this only removes the need for sudo during capture,
training, and dry-run detection.

## Real-network testing (LAN device access)

To test ACF against traffic from a genuinely external device (phone, another
PC) rather than only WSL-internal traffic:

1. Find your Windows host's LAN IP: `ipconfig` (PowerShell) -> IPv4 Address
2. Forward the dashboard port through Windows to WSL (elevated PowerShell):
   netsh interface portproxy add v4tov4 listenport=5050 listenaddress=0.0.0.0 connectport=5050 connectaddress=<current-wsl-ip>
   New-NetFirewallRule -DisplayName "ACF Dashboard" -Direction Inbound -LocalPort 5050 -Protocol TCP -Action Allow
3. Bind Flask to `0.0.0.0` (already the default in app.py)
4. Run `main.py --mode detect` alongside `app.py` to capture the traffic
5. Access from another device at `http://<windows-lan-ip>:5050`

Note: the WSL IP changes on restart, so the portproxy rule needs updating
each time. Remove both rules when done testing (see commands above, using
`delete`/`Remove-NetFirewallRule`) to avoid leaving the port open unnecessarily.

Mirrored networking mode (`networkingMode=mirrored` in `.wslconfig`) was
attempted as an alternative but failed with error 0x8007054f on this setup
(likely a Hyper-V/VPN/firewall conflict) -- the portproxy approach above
was used instead and successfully validated real external-device traffic
reaching ACF's capture pipeline.

## Running as a background service (systemd)

ACF can run continuously via systemd instead of manual terminal sessions:

```bash
sudo systemctl start acf-detect.service      # detection engine
sudo systemctl start acf-dashboard.service   # web dashboard
sudo systemctl enable acf-detect.service     # auto-start on WSL boot
sudo systemctl enable acf-dashboard.service
```

Check status: `./acf_service_status.sh`
View logs: `sudo journalctl -u acf-detect.service -f` (add `-f` to follow live)
Stop: `sudo systemctl stop acf-detect.service` / `acf-dashboard.service`

Both services auto-restart on crash (5s delay). Service files are at
`/etc/systemd/system/acf-detect.service` and `acf-dashboard.service`.

Note: WSL itself must be running for these to be active -- they start
when WSL starts, not necessarily at Windows boot, unless WSL is
separately configured to auto-launch.

## ARP spoofing detection

ACF also monitors ARP traffic for IP-to-MAC binding conflicts -- the
classic signature of ARP spoofing (an attacker impersonating another
device, often the gateway, for man-in-the-middle interception).

IMPORTANT: this is detection/alerting only, not prevention. ARP spoofing
is a Layer 2 attack; blocking the offending IP via iptables (Layer 3)
does not stop it, since the attacker remains on your local network
segment. Real mitigation requires switch-level protections (Dynamic
ARP Inspection) or static ARP entries for critical hosts like your
gateway.

Requires capturing ARP traffic: `bpf_filter` in config.yml must include
`arp` (default: `"arp or ip"`).

## DNS tunneling detection

Watches DNS queries for the classic tunneling signature: encoding data
into many unique, random-looking subdomains under one base domain
(e.g. `a8f3k2x9.tunnel.evil.com`, `b91d7xq2.tunnel.evil.com`, ...).

Two independent signals, either one triggers an alert:
  1. Many distinct subdomains under one base domain from one source,
     queried quickly (default: 15+ within 10 seconds)
  2. A single high-entropy, long subdomain label (default: 20+ chars,
     entropy >= 3.5 bits/char) -- looks like base32/64-encoded data

Tunable via dns_window_seconds, dns_min_distinct_subdomains,
dns_entropy_threshold, dns_min_label_length in config.yml.

Validated live: crafted 20 DNS queries with random subdomains under a
fake base domain, correctly triggered exactly at the configured
threshold (15th distinct subdomain).

## Stealth scan detection (NULL/FIN/XMAS)

Catches nmap's stealth scan techniques (-sN, -sF, -sX), which deliberately
avoid a normal SYN specifically to evade SYN-based scan/flood detectors:

  - NULL scan: TCP packet with no flags set at all
  - FIN scan: only the FIN flag set (no ACK -- a normal connection close
    is FIN+ACK, which is NOT flagged)
  - XMAS scan: FIN+PSH+URG all set together

These flag combinations essentially never occur in legitimate traffic, so
this is a stateless, immediate check (no tracking window needed) --
added directly to check_hybrid_rules() rather than a separate tracker
module like ARP/DNS required.

Validated live with real nmap -sN/-sF/-sX scans against a non-whitelisted
loopback address; confirmed via captured traffic (correct flag values:
'', 'F', 'FPU') and a logged alert with the correct reason.

## ICMP flood (ping flood) detection

Tracks ICMP echo request rate per source IP (default: 50+ within 5
seconds triggers an alert), reusing the same sliding-window technique
as SYN flood tracking.

HONEST NOTE on live validation: when tested (60 crafted ICMP packets to
a non-whitelisted target), the alert fired correctly but was actually
caught by the base ML anomaly model, not the icmp_flood rule specifically
-- because training data typically contains near-zero ICMP traffic, so
even a single ICMP packet already looks statistically anomalous to the
model, well before the rule's volume threshold is reached. The rule
itself is confirmed correct via unit tests (isolated, deterministic),
and serves as a backstop: if training data later includes some normal
ICMP traffic (e.g. you ping things occasionally), the ML model's
sensitivity would normalize and the rule-based threshold becomes the
primary defense against a real flood.

## Brute-force login detection

Watches for repeated connection attempts to known authentication ports
(SSH 22, Telnet 23, FTP 21, RDP 3389, MySQL 3306, PostgreSQL 5432,
MSSQL 1433, VNC 5900), using a lower/faster threshold (default: 5
attempts) than the generic repeated_port_probe rule, since real
brute-force tools hit these ports very rapidly.

Checked before the generic port-probe rule, so a match on a known auth
port gets the more specific "brute_force" label rather than the generic
one, even if both thresholds would technically be crossed.

Configurable via brute_force_ports (list) and brute_force_threshold
in config.yml.

Validated live: simulated SSH brute-force with hping3 (10 rapid SYN
packets to port 22), correctly triggered exactly at the configured
threshold (5th attempt) with the specific port identified in the alert.

## Invalid TCP flag combinations

Detects logically contradictory TCP flag combinations that never occur
in real network stacks -- only from packet-crafting tools used for
firewall/IDS evasion or OS fingerprinting:

  - SYN+FIN: a packet claiming to simultaneously open and close a connection
  - SYN+RST: a packet claiming to simultaneously open and abort a connection

Checked alongside the existing NULL/FIN/XMAS stealth scan detection in
check_hybrid_rules() -- same stateless, immediate-check pattern.

Validated live: crafted SYN+FIN packet via Scapy against a non-whitelisted
loopback target, correctly triggered with the specific reason identified.
SYN+RST uses identical logic (confirmed via unit tests); live confirmation
was complicated by the blocklist dedup correctly suppressing a repeat
alert for the same already-blocked test source IP within the same
process lifetime -- a known, correct behavior, not a detection gap.
