import os
import time
import threading
import subprocess
import requests
try:
    from netmiko import ConnectHandler
    import paramiko
except Exception:
    ConnectHandler = None
    paramiko = None
import json
import ipaddress
import re

class RuleManager:
    def __init__(
        self,
        mode="simulation",
        mgmt_ip="192.168.1.1",
        auth=("admin", "password"),
        ssh_key_file=None,
        ssh_key_passphrase=None,
    ):
        """
        Initializes the Rule Manager for either 'simulation' (iptables) 
        or 'hardware' (RESTCONF) mode.
        """
        self.mode = mode
        self.mgmt_ip = mgmt_ip
        self.auth = auth
        self.ssh_key_file = ssh_key_file or os.environ.get("ICX_KEY_FILE")
        self.ssh_key_passphrase = ssh_key_passphrase or os.environ.get("ICX_KEY_PASSPHRASE")
        self.block_interface = os.environ.get("SWITCH_BLOCK_INTERFACE", "ve 10")
        self.ssh_kex_algorithms = self._parse_ssh_algorithms(
            os.environ.get("ICX_SSH_KEX_ALGORITHMS", "diffie-hellman-group14-sha1")
        )
        self.ssh_hostkey_algorithms = self._parse_ssh_algorithms(
            os.environ.get("ICX_SSH_HOSTKEY_ALGORITHMS", "ssh-rsa")
        )
        
        # Format: {'cidr': {'expiration': float, 'rule_id': str, 'network': IPv4Network}}
        self.active_rules = {}  
        self.lock = threading.Lock()
        
        # Start background cleanup for rule TTL expiration.
        self.garbage_collector = threading.Thread(target=self._enforce_ttl, daemon=True)
        self.garbage_collector.start()

    def _build_ssh_device(self, use_key_auth: bool):
        device = {
            'device_type': 'ruckus_fastiron',
            'ip': self.mgmt_ip,
            'username': self.auth[0],
            'fast_cli': False,
            'allow_agent': False,
        }

        if use_key_auth and self.ssh_key_file:
            device['use_keys'] = True
            device['key_file'] = self.ssh_key_file
            if self.ssh_key_passphrase:
                device['passphrase'] = self.ssh_key_passphrase
        else:
            device['use_keys'] = False
            device['password'] = self.auth[1]

        return device

    def _parse_ssh_algorithms(self, value):
        if not value:
            return []
        return [item.strip() for item in value.split(',') if item.strip()]

    def _extend_paramiko_preferences(self, attr_names, algorithms, label):
        if not algorithms or paramiko is None:
            return

        transport = paramiko.transport.Transport

        if label == 'kex' and hasattr(transport, '_kex_info'):
            supported = set(transport._kex_info.keys())
            algorithms = [algo for algo in algorithms if algo in supported]
            if not algorithms:
                print(f"[SSH ACL] No supported {label} algorithms found in overrides.")
                return

        for attr_name in attr_names:
            if hasattr(transport, attr_name):
                current = list(getattr(transport, attr_name))
                for algo in algorithms:
                    if algo not in current:
                        current.append(algo)
                setattr(transport, attr_name, current)
                return

        print(f"[SSH ACL] Paramiko does not expose {label} preferences to override.")

    def _apply_paramiko_compat(self):
        self._extend_paramiko_preferences(['_preferred_kex'], self.ssh_kex_algorithms, 'kex')
        self._extend_paramiko_preferences(['_preferred_keys', '_preferred_pubkeys'], self.ssh_hostkey_algorithms, 'hostkey')

    def _connect_ssh(self):
        """Connect with key auth first, then fall back to password auth."""
        self._apply_paramiko_compat()
        attempts = []
        if self.ssh_key_file:
            attempts.append(self._build_ssh_device(use_key_auth=True))
        attempts.append(self._build_ssh_device(use_key_auth=False))

        last_error = None
        for device in attempts:
            try:
                return ConnectHandler(**device)
            except Exception as exc:
                last_error = exc

        raise last_error

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
            
            # Handle redundant or shadowed rules.
            if new_net == existing_net or new_net.subnet_of(existing_net):
                self.active_rules[existing_cidr]['expiration'] = max(data['expiration'], expiration)
                return False, existing_cidr, "Anomaly: Redundancy/Shadowing. Extended TTL of existing parent rule."
            
            # Collapse narrower rules when covered by a broader rule.
            if existing_net.subnet_of(new_net):
                rules_to_merge_and_delete.append(existing_cidr)
                
        # Remove fragmented rules replaced by the broader target rule.
        for cidr in rules_to_merge_and_delete:
            self._remove_rule(cidr)
            
        return True, str(new_net), "Conflicts resolved. Optimal rule ready for deployment."

    def deploy_block_rule(self, target_ip_or_cidr: str, duration_seconds: int = 600):
        """
        Deploys a block rule after executing conflict resolution topology logic.
        """
        # Normalize plain IP input to /32 CIDR.
        if '/' not in target_ip_or_cidr:
            target_ip_or_cidr = f"{target_ip_or_cidr}/32"

        with self.lock:
            should_deploy, optimal_cidr, msg = self._resolve_conflicts(target_ip_or_cidr, duration_seconds)
            
            if not should_deploy:
                return False, msg

            expiration = time.time() + duration_seconds

            if self.mode == "simulation":
                success = self._apply_iptables_block(optimal_cidr)
            elif self.mode == "hardware":
                # Prefer SSH-based ACL application for hardware mode
                try:
                    success = self._apply_ssh_block(optimal_cidr)
                except Exception:
                    success = self._apply_restconf_acl(optimal_cidr)
            else:
                success = False

            if success:
                self.active_rules[optimal_cidr] = {
                    'expiration': expiration,
                    'rule_id': f"BLOCK_{optimal_cidr.replace('/', '_').replace('.', '_')}",
                    'type': 'block',
                    'network': ipaddress.ip_network(optimal_cidr, strict=False)
                }
                return True, "Rule deployed successfully."
            
            return False, "Rule deployment failed."

    def _apply_iptables_block(self, target_cidr: str) -> bool:
        """Translates the verdict into a standard Linux iptables drop command."""
        try:
            # Insert at the top so explicit blocks are evaluated first.
            source_cmd = f"iptables -I INPUT 1 -s {target_cidr} -j DROP"
            destination_cmd = f"iptables -I OUTPUT 1 -d {target_cidr} -j DROP"
            subprocess.run(source_cmd.split(), check=True)
            subprocess.run(destination_cmd.split(), check=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def _apply_restconf_acl(self, target_cidr: str) -> bool:
        """Pushes an IPv4 extended ACL rule via Ruckus RESTCONF endpoints."""
        url = f"https://{self.mgmt_ip}/restconf/data/ruckus-ip:ip/access-list/extended"
        headers = {"Content-Type": "application/yang-data+json"}
        
        acl_name = f"BLOCK_{target_cidr.replace('/', '_').replace('.', '_')}"
        
        # Compute wildcard mask required by hardware ACL format.
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
                    },
                    {
                        "seq": 20,
                        "action": "deny",
                        "protocol": "ip",
                        "source": {"any": [None]},
                        "destination": {"host": network_address, "mask": wildcard_mask} if wildcard_mask != "0.0.0.0" else {"host": network_address}
                    }
                ]
            }
        }
        
        try:
            response = requests.post(url, auth=self.auth, headers=headers, data=json.dumps(payload), verify=False)
            return response.status_code in [200, 201, 204]
        except requests.exceptions.RequestException:
            return False

    def _apply_ssh_block(self, target_cidr: str) -> bool:
        """Applies an ACL on the switch via SSH using netmiko."""
        if ConnectHandler is None:
            print("[SSH ACL] netmiko not available in this environment.")
            return False

        acl_name = f"BLOCK{target_cidr.replace('/', '').replace('.', '')}"
        network_address = target_cidr.split('/')[0]
        
        print(f"[SSH ACL] Creating block rule for {network_address} with ACL name {acl_name}")

        commands = [
            'configure terminal',
            f'ip access-list extended {acl_name}',
            f'deny ip host {network_address} any',
            f'deny ip any host {network_address}',
            'exit',
            f'interface {self.block_interface}',
            f'ip access-group {acl_name} in',
            'exit',
            'write memory'
        ]
        
        print(f"[SSH ACL] Commands to send: {commands}")

        try:
            conn = self._connect_ssh()
            print(f"[SSH ACL] Connected to switch at {self.mgmt_ip}")

            conn.send_config_set(commands)
            print(f"[SSH ACL] Successfully deployed block rule for {network_address}")
            conn.disconnect()
            return True
        except Exception as e:
            import traceback
            print(f"[SSH ACL ERROR] Failed to apply SSH block for {target_cidr}: {e}")
            print(f"[SSH ACL ERROR] Traceback: {traceback.format_exc()}")
            return False

    def _remove_ssh_block(self, target_cidr: str) -> bool:
        """Removes an ACL on the switch via SSH using netmiko."""
        if ConnectHandler is None:
            print("[SSH ACL] netmiko not available in this environment.")
            return False

        acl_name = f"BLOCK{target_cidr.replace('/', '').replace('.', '')}"
        print(f"[SSH ACL] Removing block rule for {target_cidr} with ACL name {acl_name}")

        commands = [
            'configure terminal',
            f'interface {self.block_interface}',
            f'no ip access-group {acl_name} in',
            'exit',
            f'no ip access-list extended {acl_name}',
            'write memory'
        ]

        print(f"[SSH ACL] Commands to send: {commands}")

        try:
            conn = self._connect_ssh()
            print(f"[SSH ACL] Connected to switch at {self.mgmt_ip}")

            conn.send_config_set(commands)
            print(f"[SSH ACL] Successfully removed block rule for {target_cidr}")
            conn.disconnect()
            return True
        except Exception as e:
            import traceback
            print(f"[SSH ACL ERROR] Failed to remove SSH block for {target_cidr}: {e}")
            print(f"[SSH ACL ERROR] Traceback: {traceback.format_exc()}")
            return False

    def _remove_rule(self, target_cidr: str):
        """Automatically issues deletion commands based on rule type."""
        if '/' not in target_cidr and target_cidr not in self.active_rules:
            target_cidr = f"{target_cidr}/32"

        rule_data = self.active_rules.get(target_cidr, {})
        rule_type = rule_data.get('type', 'block')
        clean_ip = target_cidr.split('/')[0]
        
        if self.mode == "simulation":
            if rule_type == "block":
                source_cmd = f"iptables -D INPUT -s {target_cidr} -j DROP"
                destination_cmd = f"iptables -D OUTPUT -d {target_cidr} -j DROP"
            else:
                limit_name = f"throttle_{clean_ip.replace('.', '_')}"
                cmd = f"iptables -D INPUT -s {clean_ip} -m hashlimit --hashlimit-above 50/sec --hashlimit-burst 100 --hashlimit-mode srcip --hashlimit-name {limit_name} -j DROP"
            
            if rule_type == "block":
                subprocess.run(source_cmd.split(), check=False)
                subprocess.run(destination_cmd.split(), check=False)
            else:
                subprocess.run(cmd.split(), check=False)
            
        elif self.mode == "hardware":
            if rule_type == "block":
                try:
                    # Attempt SSH removal first
                    removed = self._remove_ssh_block(target_cidr)
                    if not removed:
                        # Fallback to RESTCONF delete if SSH removal failed
                        acl_name = f"BLOCK_{target_cidr.replace('/', '_').replace('.', '_')}"
                        url = f"https://{self.mgmt_ip}/restconf/data/ruckus-ip:ip/access-list/extended={acl_name}"
                        try:
                            requests.delete(url, auth=self.auth, verify=False)
                        except requests.exceptions.RequestException:
                            pass
                except Exception:
                    pass
            else:
                policy_name = f"THROTTLE_{clean_ip.replace('.', '_')}"
                url = f"https://{self.mgmt_ip}/restconf/data/ruckus-qos:qos/traffic-policies/policy={policy_name}"
                
                try:
                    requests.delete(url, auth=self.auth, verify=False)
                except requests.exceptions.RequestException:
                    pass
            
        if target_cidr in self.active_rules:
            del self.active_rules[target_cidr]

    def list_switch_block_rules(self):
        """Return block rules currently configured on the switch."""
        if ConnectHandler is None:
            print("[SSH ACL] netmiko not available in this environment.")
            return None

        try:
            conn = self._connect_ssh()
            output = conn.send_command('show ip access-list')
            conn.disconnect()
        except Exception as e:
            print(f"[SSH ACL ERROR] Failed to read switch ACLs: {e}")
            return None

        rules = []
        current_acl = None
        current_acl_name = None
        seen_ips = set()  # Track IPs already added to avoid duplicates

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            acl_match = re.match(r'^(Extended IP access list|IP access list extended)\s+(\S+)', line, re.IGNORECASE)
            if acl_match:
                current_acl_name = acl_match.group(2)
                current_acl = []
                seen_ips.clear()
                continue

            if current_acl_name and re.match(r'^\d+:\s*deny ip', line, re.IGNORECASE):
                # Capture both "deny ip host X any" and "deny ip any host X" patterns
                host_match = re.search(r'deny ip host ([0-9.]+) any', line, re.IGNORECASE)
                if not host_match:
                    host_match = re.search(r'deny ip any host ([0-9.]+)', line, re.IGNORECASE)
                
                if host_match:
                    ip_address = host_match.group(1)
                    # Only add once per IP per ACL to avoid duplicates from bidirectional rules
                    if ip_address not in seen_ips:
                        seen_ips.add(ip_address)
                        rules.append({
                            'ip_address': ip_address,
                            'action': 'BLOCK',
                            'rule_type': 'PERMANENT',
                            'port': None,
                            'notes': f'Imported from switch ACL {current_acl_name}',
                            'status': 'ACTIVE',
                            'acl_name': current_acl_name,
                        })

        return rules

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

    def deploy_rate_limit_rule(self, target_ip: str, max_packets_per_second: int = 50, duration_seconds: int = 300):
        """
        Deploys a rate-limiting rule to throttle bandwidth for ambiguous flows.
        """
        # Use plain IP for hashlimit rule naming.
        clean_ip = target_ip.split('/')[0]

        with self.lock:
            # Extend TTL if a rule already exists for this host.
            if clean_ip in self.active_rules:
                self.active_rules[clean_ip]['expiration'] = max(self.active_rules[clean_ip]['expiration'], time.time() + duration_seconds)
                return False, "Rule redundant. TTL extended."

            expiration = time.time() + duration_seconds
            rule_id = f"THROTTLE_{clean_ip.replace('.', '_')}"

            if self.mode == "simulation":
                success = self._apply_iptables_throttle(clean_ip, max_packets_per_second)
            elif self.mode == "hardware":
                success = self._apply_restconf_throttle(clean_ip, max_packets_per_second)
            else:
                success = False

            if success:
                self.active_rules[clean_ip] = {
                    'expiration': expiration,
                    'rule_id': rule_id,
                    'type': 'throttle',
                    'network': ipaddress.ip_network(f"{clean_ip}/32", strict=False)
                }
                return True, f"Bandwidth throttled to {max_packets_per_second} pps."
            
            return False, "Rate limit deployment failed."

    def _apply_iptables_throttle(self, target_ip: str, limit: int) -> bool:
        """
        Uses the Linux hashlimit module to drop packets ONLY when they exceed 
        the allowed bandwidth threshold, effectively rate-limiting the connection.
        """
        try:
            limit_name = f"throttle_{target_ip.replace('.', '_')}"
            cmd = (f"iptables -I INPUT 1 -s {target_ip} -m hashlimit "
                   f"--hashlimit-above {limit}/sec --hashlimit-burst {limit * 2} "
                   f"--hashlimit-mode srcip --hashlimit-name {limit_name} -j DROP")
            subprocess.run(cmd.split(), check=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def _apply_restconf_throttle(self, target_ip: str, limit: int) -> bool:
        """
        Pushes a QoS Rate-Limiting/Policing policy to the Ruckus switch via RESTCONF.
        """
        url = f"https://{self.mgmt_ip}/restconf/data/ruckus-qos:qos/traffic-policies"
        headers = {"Content-Type": "application/yang-data+json"}
        
        policy_name = f"THROTTLE_{target_ip.replace('.', '_')}"
        
        payload = {
            "traffic-policies": {
                "policy": [
                    {
                        "name": policy_name,
                        "rate-limit": limit * 1500 * 8,
                        "action": "drop"
                    }
                ]
            }
        }
        
        try:
            requests.post(url, auth=self.auth, headers=headers, data=json.dumps(payload), verify=False)
            return True
        except requests.exceptions.RequestException:
            return False