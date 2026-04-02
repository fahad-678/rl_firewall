import os
import time
import threading
import subprocess
import requests
import json
import ipaddress

class RuleManager:
    def __init__(self, mode="simulation", mgmt_ip="192.168.1.1", auth=("admin", "password")):
        """
        Initializes the Rule Manager for either 'simulation' (iptables) 
        or 'hardware' (RESTCONF) mode.
        """
        self.mode = mode
        self.mgmt_ip = mgmt_ip
        self.auth = auth
        
        # Format: { 'cidr_string': {'expiration': float, 'rule_id': str, 'network': IPv4Network} }
        self.active_rules = {}  
        self.lock = threading.Lock()
        
        # Start the background thread to handle rule Time-To-Live (TTL) aging
        self.garbage_collector = threading.Thread(target=self._enforce_ttl, daemon=True)
        self.garbage_collector.start()

    def _resolve_conflicts(self, target_cidr: str, duration_seconds: int):
        """
        Actively parses the existing ruleset to identify and resolve primary types 
        of firewall anomalies prior to inserting a new rule.
        """
        new_net = ipaddress.ip_network(target_cidr, strict=False)
        expiration = time.time() + duration_seconds
        
        rules_to_merge_and_delete = []
        
        for existing_cidr, data in self.active_rules.items():
            existing_net = data['network']
            
            # 1. REDUNDANCY & SHADOWING RESOLUTION
            # If the new rule matches the exact same packet space, OR if the new rule
            # is a smaller subset of a broader block rule already deployed (shadowed).
            if new_net == existing_net or new_net.subnet_of(existing_net):
                # The redundant rule provides no additional security and only consumes memory.
                # We simply extend the TTL of the existing rule to match the new request.
                self.active_rules[existing_cidr]['expiration'] = max(data['expiration'], expiration)
                return False, existing_cidr, "Anomaly: Redundancy/Shadowing. Extended TTL of existing parent rule."
            
            # 2. OVERLAPPING RESOLUTION
            # If rules mandate the same action for overlapping but not identical packet subspaces 
            # (e.g., the new rule is a /24 subnet, but we already have three /32 rules inside it).
            if existing_net.subnet_of(new_net):
                # The continuous segments are merged into a single, comprehensive rule.
                # We flag the old, smaller rules for deletion.
                rules_to_merge_and_delete.append(existing_cidr)
                
        # Execute the merge operations (cleaning up the fragmented rules)
        for cidr in rules_to_merge_and_delete:
            self._remove_rule(cidr)
            
        return True, str(new_net), "Conflicts resolved. Optimal rule ready for deployment."

    def deploy_block_rule(self, target_ip_or_cidr: str, duration_seconds: int = 600):
        """
        Deploys a block rule after executing conflict resolution topology logic.
        """
        # Ensure we are working with CIDR notation (e.g., 192.168.1.5 -> 192.168.1.5/32)
        if '/' not in target_ip_or_cidr:
            target_ip_or_cidr = f"{target_ip_or_cidr}/32"

        with self.lock:
            # Phase 3: Algorithmic Conflict Resolution
            should_deploy, optimal_cidr, msg = self._resolve_conflicts(target_ip_or_cidr, duration_seconds)
            
            if not should_deploy:
                # The conflict resolver handled it (e.g., by extending an existing TTL)
                return False, msg

            expiration = time.time() + duration_seconds

            if self.mode == "simulation":
                success = self._apply_iptables_block(optimal_cidr)
            elif self.mode == "hardware":
                success = self._apply_restconf_acl(optimal_cidr)
            else:
                success = False

            if success:
                self.active_rules[optimal_cidr] = {
                    'expiration': expiration,
                    'rule_id': f"BLOCK_{optimal_cidr.replace('/', '_').replace('.', '_')}",
                    'network': ipaddress.ip_network(optimal_cidr, strict=False)
                }
                return True, "Rule deployed successfully."
            
            return False, "Rule deployment failed."

    def _apply_iptables_block(self, target_cidr: str) -> bool:
        """Translates the verdict into a standard Linux iptables drop command."""
        try:
            # We insert at the top (-I INPUT 1) to ensure explicit blocks 
            # precede generalized allow directives.
            cmd = f"iptables -I INPUT 1 -s {target_cidr} -j DROP"
            subprocess.run(cmd.split(), check=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def _apply_restconf_acl(self, target_cidr: str) -> bool:
        """Pushes an IPv4 extended ACL rule via Ruckus RESTCONF endpoints."""
        url = f"https://{self.mgmt_ip}/restconf/data/ruckus-ip:ip/access-list/extended"
        headers = {"Content-Type": "application/yang-data+json"}
        
        acl_name = f"BLOCK_{target_cidr.replace('/', '_').replace('.', '_')}"
        
        # Calculate wildcard mask required for hardware ACLs from CIDR
        network = ipaddress.ip_network(target_cidr, strict=False)
        wildcard_mask = str(network.hostmask)
        network_address = str(network.network_address)
        
        payload = {
            "extended": {
                "name": acl_name,
                "rule": [
                    {
                        "seq": 10,
                        "action": "deny",
                        "protocol": "ip",
                        "source": {"host": network_address, "mask": wildcard_mask} if wildcard_mask != "0.0.0.0" else {"host": network_address},
                        "destination": {"any": [None]}
                    }
                ]
            }
        }
        
        try:
            response = requests.post(url, auth=self.auth, headers=headers, data=json.dumps(payload), verify=False)
            return response.status_code in [200, 201, 204]
        except requests.exceptions.RequestException:
            return False

    def _remove_rule(self, target_cidr: str):
        """Automatically issues deletion commands."""
        if self.mode == "simulation":
            cmd = f"iptables -D INPUT -s {target_cidr} -j DROP"
            subprocess.run(cmd.split(), check=False)
        elif self.mode == "hardware":
            acl_name = f"BLOCK_{target_cidr.replace('/', '_').replace('.', '_')}"
            url = f"https://{self.mgmt_ip}/restconf/data/ruckus-ip:ip/access-list/extended={acl_name}"
            try:
                requests.delete(url, auth=self.auth, verify=False)
            except requests.exceptions.RequestException:
                pass
            
        if target_cidr in self.active_rules:
            del self.active_rules[target_cidr]

    def _enforce_ttl(self):
        """Garbage collection for expired rules."""
        while True:
            time.sleep(10) 
            current_time = time.time()
            expired_cidrs = []
            
            with self.lock:
                for cidr, data in self.active_rules.items():
                    if current_time > data['expiration']:
                        expired_cidrs.append(cidr)
                
                for cidr in expired_cidrs:
                    self._remove_rule(cidr)