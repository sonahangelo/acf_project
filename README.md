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
