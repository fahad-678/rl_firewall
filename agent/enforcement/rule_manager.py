import os
import time
import threading
import subprocess
import requests
import json

class RuleManager:
    def __init__(self, mode="simulation", mgmt_ip="192.168.1.1", auth=("admin", "password")):
        """
        Initializes the Rule Manager for either 'simulation' (iptables) 
        or 'hardware' (RESTCONF) mode[cite: 87, 88].
        """
        self.mode = mode
        self.mgmt_ip = mgmt_ip
        self.auth = auth
        self.active_rules = {}  # Format: { 'ip_address': {'expiration': float, 'rule_id': str} }
        self.lock = threading.Lock()
        
        # Start the background thread to handle rule Time-To-Live (TTL) aging [cite: 106, 107]
        self.garbage_collector = threading.Thread(target=self._enforce_ttl, daemon=True)
        self.garbage_collector.start()

    def deploy_block_rule(self, source_ip: str, duration_seconds: int = 600):
        """
        Deploys a block rule for a malicious IP with a specified Time-To-Live (TTL)[cite: 106, 107].
        Resolves basic redundancies before applying the rule[cite: 104, 105].
        """
        with self.lock:
            # Conflict Resolution: Redundancy Check [cite: 104, 105]
            if source_ip in self.active_rules:
                # If the rule already exists, just extend the TTL instead of creating a duplicate
                self.active_rules[source_ip]['expiration'] = time.time() + duration_seconds
                return False, "Rule redundant. TTL extended."

            expiration = time.time() + duration_seconds

            if self.mode == "simulation":
                success = self._apply_iptables_block(source_ip)
            elif self.mode == "hardware":
                success = self._apply_restconf_acl(source_ip)
            else:
                success = False

            if success:
                self.active_rules[source_ip] = {
                    'expiration': expiration,
                    'rule_id': f"BLOCK_{source_ip}"
                }
                return True, "Rule deployed successfully."
            
            return False, "Rule deployment failed."

    def _apply_iptables_block(self, source_ip: str) -> bool:
        """Translates the verdict into a standard Linux iptables drop command."""
        try:
            # We insert at the top (-I INPUT 1) to prevent shadowing by broader allow rules [cite: 104]
            cmd = f"iptables -I INPUT 1 -s {source_ip} -j DROP"
            subprocess.run(cmd.split(), check=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def _apply_restconf_acl(self, source_ip: str) -> bool:
        """
        Pushes an IPv4 extended ACL rule defining a deny action via RESTCONF[cite: 94].
        Formats the payload according to the Ruckus YANG schema[cite: 95].
        """
        url = f"https://{self.mgmt_ip}/restconf/data/ruckus-ip:ip/access-list/extended"
        headers = {"Content-Type": "application/yang-data+json"}
        
        # Crafting the JSON payload defined by standard YANG data models [cite: 90, 95]
        payload = {
            "extended": {
                "name": f"BLOCK_{source_ip.replace('.', '_')}",
                "rule": [
                    {
                        "seq": 10,
                        "action": "deny",
                        "protocol": "ip",
                        "source": {"host": source_ip},
                        "destination": {"any": [null]}
                    }
                ]
            }
        }
        
        try:
            response = requests.post(
                url, 
                auth=self.auth, 
                headers=headers, 
                data=json.dumps(payload), 
                verify=False # Bypass SSL verification for internal mgmt interfaces
            )
            return response.status_code in [200, 201, 204]
        except requests.exceptions.RequestException:
            return False

    def _remove_rule(self, source_ip: str):
        """Automatically issues deletion commands when a rule expires[cite: 107]."""
        if self.mode == "simulation":
            cmd = f"iptables -D INPUT -s {source_ip} -j DROP"
            subprocess.run(cmd.split(), check=False)
        elif self.mode == "hardware":
            acl_name = f"BLOCK_{source_ip.replace('.', '_')}"
            url = f"https://{self.mgmt_ip}/restconf/data/ruckus-ip:ip/access-list/extended={acl_name}"
            requests.delete(url, auth=self.auth, verify=False)
            
        if source_ip in self.active_rules:
            del self.active_rules[source_ip]

    def _enforce_ttl(self):
        """
        Background worker that continuously scans the active rule table.
        Guarantees that the firewall table remains lean to preserve packet switching throughput.
        """
        while True:
            time.sleep(10) # Check every 10 seconds
            current_time = time.time()
            expired_ips = []
            
            with self.lock:
                for ip, data in self.active_rules.items():
                    if current_time > data['expiration']:
                        expired_ips.append(ip)
                
                # Delete expired rules [cite: 107]
                for ip in expired_ips:
                    self._remove_rule(ip)