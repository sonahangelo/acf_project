
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
