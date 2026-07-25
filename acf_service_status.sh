#!/bin/bash
echo "=== ACF Detection ==="
sudo systemctl is-active acf-detect.service
echo "=== ACF Dashboard ==="
sudo systemctl is-active acf-dashboard.service
echo ""
echo "Dashboard: http://127.0.0.1:5050"
echo "Recent detect logs: sudo journalctl -u acf-detect.service -n 50 --no-pager"
echo "Recent dashboard logs: sudo journalctl -u acf-dashboard.service -n 50 --no-pager"
