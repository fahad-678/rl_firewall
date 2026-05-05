#!/usr/bin/env python3
"""Simple test utility to verify SSH ACL deployment to the ICX 7150.

Run this inside the `agent` container after `docker-compose up`:

    python3 /app/tools/test_switch_acl.py

It will attempt to deploy a temporary block for a TEST-NET IP and report the result.
"""
import os
import time
import sys
from pathlib import Path

# Ensure /app is on sys.path when this script is executed directly from /app/tools.
APP_ROOT = Path(__file__).resolve().parents[1]
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from enforcement.rule_manager import RuleManager


def main():
    mgmt_ip = os.environ.get('ICX_MGMT_IP', '192.168.1.50')
    user = os.environ.get('ICX_USER', 'admin')
    passwd = os.environ.get('ICX_PASSWORD', 'adminadmin')

    print(f"Connecting to switch {mgmt_ip} as {user}...")
    rm = RuleManager(mode='hardware', mgmt_ip=mgmt_ip, auth=(user, passwd))

    test_ip = os.environ.get('TEST_BLOCK_IP', '198.51.100.5')
    print(f"Deploying test block for {test_ip} for 120 seconds...")
    ok, msg = rm.deploy_block_rule(test_ip, duration_seconds=120)
    print(f"Result: {ok} - {msg}")

    if ok:
        print("Waiting 5s before removal check...")
        time.sleep(5)
        print("If successful, check the switch 'show access-list' to confirm the ACL exists.")
    else:
        print("SSH/ACL deployment failed. Check container network, credentials, and compatibility.")


if __name__ == '__main__':
    main()
