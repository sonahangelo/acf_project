
## Setup: avoiding sudo for capture

Packet capture requires raw socket access. Instead of running everything
under `sudo`, grant the capability directly to the system Python binary:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
```

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
