import os
import math
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

# Caller identity for mutations on active_rules. Manual entries are immune to AI,
# TTL and analyst (dashboard "Revoke Block") callers.
CALLER_AI = 'ai'
CALLER_MANUAL = 'manual'
CALLER_TTL = 'ttl'
CALLER_ANALYST = 'analyst'

# ACL name prefixes — used in hardware mode so the switch importer can
# distinguish AI-deployed ACLs (skip on import) from manual ones.
ACL_PREFIX_AI_BLOCK = 'AI_BLOCK_'
ACL_PREFIX_MANUAL_BLOCK = 'MAN_BLOCK_'
ACL_PREFIX_MANUAL_ALLOW = 'MAN_ALLOW_'

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

        # active_rules[cidr] = {
        #     'expiration': float (math.inf for manual rules),
        #     'rule_id': str, 'type': 'block'|'throttle',
        #     'verdict': 'block'|'allow'|'throttle',
        #     'origin': 'manual'|'ai',
        #     'network': IPv4Network,
        #     'port': int|None,
        # }
        self.active_rules = {}
        self.lock = threading.Lock()

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

    @staticmethod
    def _normalize_cidr(ip_or_cidr: str) -> str:
        if '/' not in ip_or_cidr:
            return f"{ip_or_cidr}/32"
        return ip_or_cidr

    def _is_protected_nolock(self, ip_or_cidr: str):
        """
        Return the matching manual rule entry if ip_or_cidr is covered by any
        active manual-origin rule. Caller MUST hold self.lock.
        """
        try:
            target = ipaddress.ip_network(self._normalize_cidr(ip_or_cidr), strict=False)
        except (ValueError, TypeError):
            return None

        for cidr, data in self.active_rules.items():
            if data.get('origin') != CALLER_MANUAL:
                continue
            existing = data['network']
            # Manual rule covers target if target ⊆ existing, OR target overlaps existing
            # (e.g. AI tries to block /24 containing a manual /32 ALLOW).
            if target.subnet_of(existing) or existing.subnet_of(target):
                return {'cidr': cidr, **data}
        return None

    def is_protected(self, ip_or_cidr: str):
        with self.lock:
            return self._is_protected_nolock(ip_or_cidr)

    def _resolve_conflicts(self, target_cidr: str, duration_seconds: int, origin: str):
        """
        Resolve overlaps with existing rules. For AI-origin deploys, any conflict with
        a manual entry is fatal (caller must abort). For manual-origin deploys, manual
        entries are still respected (never mutated) but AI entries can be evicted.
        """
        new_net = ipaddress.ip_network(target_cidr, strict=False)
        expiration = time.time() + duration_seconds if duration_seconds != math.inf else math.inf
        rules_to_evict = []

        for existing_cidr, data in self.active_rules.items():
            existing_net = data['network']
            existing_is_manual = data.get('origin') == CALLER_MANUAL

            # If new rule is contained in or equal to an existing rule:
            if new_net == existing_net or new_net.subnet_of(existing_net):
                if existing_is_manual:
                    # Manual rule already covers this — refuse AI deploy.
                    if origin == CALLER_AI:
                        return False, existing_cidr, "CONFLICTS_WITH_MANUAL_RULE"
                    # Manual re-registering same/narrower CIDR: idempotent no-op.
                    return False, existing_cidr, "REDUNDANT_MANUAL_RULE"
                # AI-existing redundant rule: extend TTL.
                if expiration != math.inf:
                    self.active_rules[existing_cidr]['expiration'] = max(
                        data['expiration'], expiration
                    )
                return False, existing_cidr, "Redundant. Extended TTL of existing rule."

            # If new rule is broader than an existing rule:
            if existing_net.subnet_of(new_net):
                if existing_is_manual:
                    # Cannot collapse a manual rule into a broader AI rule.
                    if origin == CALLER_AI:
                        return False, existing_cidr, "CONFLICTS_WITH_MANUAL_RULE"
                    # Manual deploying a broader CIDR containing existing manual narrower:
                    # keep both; don't evict the narrower manual.
                    continue
                rules_to_evict.append(existing_cidr)

        # Evict only AI-origin narrower rules (manual entries are skipped above).
        for cidr in rules_to_evict:
            self._remove_rule(cidr, caller=origin)

        return True, str(new_net), "Conflicts resolved. Optimal rule ready for deployment."

    def deploy_block_rule(self, target_ip_or_cidr: str, duration_seconds: int = 600, origin: str = CALLER_AI):
        """
        Deploys a block rule. AI-origin deploys are skipped if the target overlaps
        any manual rule.
        """
        target_ip_or_cidr = self._normalize_cidr(target_ip_or_cidr)

        with self.lock:
            if origin == CALLER_AI:
                protected = self._is_protected_nolock(target_ip_or_cidr)
                if protected is not None:
                    return False, "BLOCKED_BY_MANUAL_RULE", protected

            should_deploy, optimal_cidr, msg = self._resolve_conflicts(
                target_ip_or_cidr, duration_seconds, origin
            )

            if not should_deploy:
                return False, msg, None

            expiration = (
                math.inf if duration_seconds == math.inf else time.time() + duration_seconds
            )

            if self.mode == "simulation":
                success = self._apply_iptables_block(optimal_cidr)
            elif self.mode == "hardware":
                try:
                    success = self._apply_ssh_block(optimal_cidr, origin=origin)
                except Exception:
                    success = self._apply_restconf_acl(optimal_cidr, origin=origin)
            else:
                success = False

            if success:
                prefix = ACL_PREFIX_MANUAL_BLOCK if origin == CALLER_MANUAL else ACL_PREFIX_AI_BLOCK
                self.active_rules[optimal_cidr] = {
                    'expiration': expiration,
                    'rule_id': f"{prefix}{optimal_cidr.replace('/', '_').replace('.', '_')}",
                    'type': 'block',
                    'verdict': 'block',
                    'origin': origin,
                    'network': ipaddress.ip_network(optimal_cidr, strict=False),
                    'port': None,
                }
                return True, "Rule deployed successfully.", None

            return False, "Rule deployment failed.", None

    def register_manual_rule(self, ip_or_cidr: str, verdict: str, port=None):
        """
        Register a manual rule. Verdict is 'BLOCK' or 'ALLOW' (case-insensitive).
        BLOCK applies iptables drop or switch ACL. ALLOW inserts an explicit
        ACCEPT at iptables INPUT/OUTPUT position 1 (or permit-host on the switch),
        which the AI cannot overwrite.

        Idempotent: re-registering the same CIDR is a no-op (handles the pubsub +
        poller double-write race).
        """
        verdict = (verdict or '').strip().upper()
        if verdict not in ('BLOCK', 'ALLOW'):
            return False, "Invalid verdict for manual rule."

        cidr = self._normalize_cidr(ip_or_cidr)

        if verdict == 'BLOCK':
            return self.deploy_block_rule(cidr, duration_seconds=math.inf, origin=CALLER_MANUAL)

        # ALLOW path.
        with self.lock:
            # Idempotent: same CIDR already registered as manual ALLOW → no-op.
            existing = self.active_rules.get(cidr)
            if existing is not None and existing.get('origin') == CALLER_MANUAL and existing.get('verdict') == 'allow':
                return False, "Manual ALLOW already registered."

            # Evict any existing AI block on this CIDR (the analyst's ALLOW wins).
            if existing is not None and existing.get('origin') == CALLER_AI:
                self._remove_rule(cidr, caller=CALLER_MANUAL)

            if self.mode == "simulation":
                success = self._apply_iptables_allow(cidr)
            elif self.mode == "hardware":
                try:
                    success = self._apply_ssh_allow(cidr)
                except Exception:
                    success = False
            else:
                success = False

            if success:
                self.active_rules[cidr] = {
                    'expiration': math.inf,
                    'rule_id': f"{ACL_PREFIX_MANUAL_ALLOW}{cidr.replace('/', '_').replace('.', '_')}",
                    'type': 'allow',
                    'verdict': 'allow',
                    'origin': CALLER_MANUAL,
                    'network': ipaddress.ip_network(cidr, strict=False),
                    'port': port,
                }
                return True, "Manual ALLOW rule registered."

            return False, "Manual ALLOW deployment failed."

    def unregister_manual_rule(self, ip_or_cidr: str):
        """Removes a manual rule. Caller is implicitly CALLER_MANUAL."""
        cidr = self._normalize_cidr(ip_or_cidr)
        with self.lock:
            data = self.active_rules.get(cidr)
            if data is None or data.get('origin') != CALLER_MANUAL:
                return False, "No manual rule registered for this CIDR."
            self._remove_rule(cidr, caller=CALLER_MANUAL)
            return True, "Manual rule unregistered."

    def deploy_dos_mitigate_rule(self, target_ip: str, flow_metrics: dict):
        """
        Deploys adaptive DOS mitigation based on attack intensity.
        
        Tiering logic:
        - PPS > 10,000: Full block for 1200s (mega-attack)
        - Conn density > 30: Rate-limit to 50 pps for 600s (connection exhaustion)
        - Synchronized flag: Block for 900s (DDoS pattern detected)
        - Otherwise: Rate-limit to 100 pps for 300s (moderate DOS)
        
        flow_metrics: dict with keys:
            - packets_per_sec: float
            - source_conn_density: float
            - synchronized_flag: bool
        """
        target_cidr = self._normalize_cidr(target_ip)
        
        pps = flow_metrics.get('packets_per_sec', 0.0)
        conn_density = flow_metrics.get('source_conn_density', 0.0)
        synchronized = flow_metrics.get('synchronized_flag', False)
        
        # Tier 1: Volumetric mega-attack
        if pps > 10000:
            print(f"[DOS] Tier 1 mega-attack detected: {target_ip} at {pps:.0f} pps → BLOCK 1200s")
            return self.deploy_block_rule(target_cidr, duration_seconds=1200, origin=CALLER_AI)
        
        # Tier 2: Connection exhaustion
        if conn_density > 30:
            print(f"[DOS] Tier 2 connection exhaustion: {target_ip} with {conn_density:.1f} conn/max → RATE_LIMIT 50pps 600s")
            return self.deploy_rate_limit_rule(target_cidr, limit_pps=50, duration_seconds=600, origin=CALLER_AI)
        
        # Tier 3: DDoS pattern
        if synchronized:
            print(f"[DOS] Tier 3 DDoS pattern: {target_ip} → BLOCK 900s")
            return self.deploy_block_rule(target_cidr, duration_seconds=900, origin=CALLER_AI)
        
        # Tier 4: Moderate DOS
        print(f"[DOS] Tier 4 moderate: {target_ip} at {pps:.0f} pps → RATE_LIMIT 100pps 300s")
        return self.deploy_rate_limit_rule(target_cidr, limit_pps=100, duration_seconds=300, origin=CALLER_AI)

    def deploy_rate_limit_rule(self, target_ip_or_cidr: str, limit_pps: int, duration_seconds: int = 300, origin: str = CALLER_AI):
        """
        Deploys a rate-limiting rule using Linux tc (traffic control).
        
        Limits target CIDR to limit_pps packets per second.
        """
        target_cidr = self._normalize_cidr(target_ip_or_cidr)
        
        with self.lock:
            if origin == CALLER_AI:
                protected = self._is_protected_nolock(target_cidr)
                if protected is not None:
                    return False, "BLOCKED_BY_MANUAL_RULE", protected
            
            should_deploy, optimal_cidr, msg = self._resolve_conflicts(
                target_cidr, duration_seconds, origin
            )
            
            if not should_deploy:
                return False, msg, None
            
            if self.mode == "simulation":
                success = self._apply_tc_rate_limit(optimal_cidr, limit_pps)
            elif self.mode == "hardware":
                # Hardware mode: try SSH to apply QoS, then fallback to local TC
                try:
                    success = self._apply_ssh_rate_limit(optimal_cidr, limit_pps)
                except Exception:
                    success = self._apply_tc_rate_limit(optimal_cidr, limit_pps)
            else:
                success = False
            
            if success:
                expiration = time.time() + duration_seconds if duration_seconds != math.inf else math.inf
                prefix = "MANUAL_RATELIMIT_" if origin == CALLER_MANUAL else "AI_RATELIMIT_"
                self.active_rules[optimal_cidr] = {
                    'expiration': expiration,
                    'rule_id': f"{prefix}{optimal_cidr.replace('/', '_').replace('.', '_')}",
                    'type': 'throttle',
                    'verdict': 'throttle',
                    'origin': origin,
                    'network': ipaddress.ip_network(optimal_cidr, strict=False),
                    'port': None,
                    'limit_pps': limit_pps,
                }
                return True, "Rate-limit rule deployed successfully.", None
            
            return False, "Rate-limit rule deployment failed.", None

    def _apply_tc_rate_limit(self, target_cidr: str, limit_pps: int) -> bool:
        """
        Uses Linux tc (traffic control) to rate-limit packets from target CIDR.
        Implements a simple token bucket queueing discipline.
        """
        try:
            # Extract IP for filtering
            target_ip = target_cidr.split('/')[0]
            interface = os.environ.get("TC_INTERFACE", "lo")  # Default to loopback for docker
            
            # Calculate burst size (1ms worth of packets)
            burst = max(1, limit_pps // 1000)
            
            # Add HTB (Hierarchical Token Bucket) qdisc and class
            # Root qdisc
            cmd = f"tc qdisc add dev {interface} root handle 1: htb default 12"
            subprocess.run(cmd.split(), check=False)
            
            # Class with rate limit
            rate_str = f"{limit_pps}pps"
            cmd = f"tc class add dev {interface} parent 1: classid 1:1 htb rate {rate_str} burst {burst}b"
            subprocess.run(cmd.split(), check=False)
            
            # Filter to match source IP
            cmd = f"tc filter add dev {interface} parent 1: protocol ip prio 1 u32 match ip src {target_ip} flowid 1:1"
            subprocess.run(cmd.split(), check=False)
            
            print(f"[TC] Rate-limit applied: {target_cidr} → {limit_pps} pps on {interface}")
            return True
        except Exception as e:
            print(f"[TC] Rate-limit failed: {e}")
            return False

    def _apply_ssh_rate_limit(self, target_cidr: str, limit_pps: int) -> bool:
        """
        Applies rate-limiting on the switch via SSH using QoS policy.
        Ruckus ICX 7150 specific implementation.
        """
        if not ConnectHandler:
            return False
        
        try:
            conn = self._connect_ssh()
            target_ip = target_cidr.split('/')[0]
            policy_name = f"RATELIMIT_{target_ip.replace('.', '_')}"
            
            commands = [
                f"configure terminal",
                f"policy-map {policy_name}",
                f"  class 1",
                f"    police 1000 500",  # 1000 pps, 500 pps burst
                f"exit",
                f"exit",
                f"interface {self.block_interface}",
                f"  service-policy output {policy_name}",
                f"write memory",
            ]
            
            for cmd in commands:
                conn.send_command(cmd)
            
            conn.disconnect()
            print(f"[SSH] Rate-limit via QoS: {target_cidr} on {self.block_interface}")
            return True
        except Exception as e:
            print(f"[SSH] Rate-limit failed: {e}")
            return False

    def _apply_iptables_block(self, target_cidr: str) -> bool:
        """Translates the verdict into a standard Linux iptables drop command."""
        try:
            source_cmd = f"iptables -I INPUT 1 -s {target_cidr} -j DROP"
            destination_cmd = f"iptables -I OUTPUT 1 -d {target_cidr} -j DROP"
            subprocess.run(source_cmd.split(), check=True)
            subprocess.run(destination_cmd.split(), check=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def _apply_iptables_allow(self, target_cidr: str) -> bool:
        """
        Inserts an explicit ACCEPT at the top of INPUT/OUTPUT so any later DROP
        the AI tries to push cannot block this CIDR.
        """
        try:
            source_cmd = f"iptables -I INPUT 1 -s {target_cidr} -j ACCEPT"
            destination_cmd = f"iptables -I OUTPUT 1 -d {target_cidr} -j ACCEPT"
            subprocess.run(source_cmd.split(), check=True)
            subprocess.run(destination_cmd.split(), check=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def _remove_iptables_allow(self, target_cidr: str) -> None:
        source_cmd = f"iptables -D INPUT -s {target_cidr} -j ACCEPT"
        destination_cmd = f"iptables -D OUTPUT -d {target_cidr} -j ACCEPT"
        subprocess.run(source_cmd.split(), check=False)
        subprocess.run(destination_cmd.split(), check=False)

    def _apply_restconf_acl(self, target_cidr: str, origin: str = CALLER_AI) -> bool:
        """Pushes an IPv4 extended ACL rule via Ruckus RESTCONF endpoints."""
        url = f"https://{self.mgmt_ip}/restconf/data/ruckus-ip:ip/access-list/extended"
        headers = {"Content-Type": "application/yang-data+json"}

        prefix = ACL_PREFIX_MANUAL_BLOCK if origin == CALLER_MANUAL else ACL_PREFIX_AI_BLOCK
        acl_name = f"{prefix}{target_cidr.replace('/', '_').replace('.', '_')}"

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

    @staticmethod
    def _ssh_acl_name(target_cidr: str, origin: str) -> str:
        prefix = ACL_PREFIX_MANUAL_BLOCK if origin == CALLER_MANUAL else ACL_PREFIX_AI_BLOCK
        return f"{prefix}{target_cidr.replace('/', '_').replace('.', '_')}"

    def _apply_ssh_block(self, target_cidr: str, origin: str = CALLER_AI) -> bool:
        """Applies an ACL on the switch via SSH using netmiko."""
        if ConnectHandler is None:
            print("[SSH ACL] netmiko not available in this environment.")
            return False

        acl_name = self._ssh_acl_name(target_cidr, origin)
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

        try:
            conn = self._connect_ssh()
            conn.send_config_set(commands)
            print(f"[SSH ACL] Successfully deployed block rule for {network_address}")
            conn.disconnect()
            return True
        except Exception as e:
            import traceback
            print(f"[SSH ACL ERROR] Failed to apply SSH block for {target_cidr}: {e}")
            print(f"[SSH ACL ERROR] Traceback: {traceback.format_exc()}")
            return False

    def _apply_ssh_allow(self, target_cidr: str) -> bool:
        """Permits the host via a dedicated MANUAL_ALLOWLIST ACL applied first."""
        if ConnectHandler is None:
            print("[SSH ACL] netmiko not available in this environment.")
            return False

        acl_name = 'MANUAL_ALLOWLIST'
        network_address = target_cidr.split('/')[0]
        permit_in = f'permit ip host {network_address} any'
        permit_out = f'permit ip any host {network_address}'

        commands = [
            'configure terminal',
            f'ip access-list extended {acl_name}',
            permit_in,
            permit_out,
            'exit',
            f'interface {self.block_interface}',
            f'ip access-group {acl_name} in',
            'exit',
            'write memory'
        ]

        try:
            conn = self._connect_ssh()
            conn.send_config_set(commands)
            print(f"[SSH ACL] Manual ALLOW registered for {network_address} in {acl_name}")
            conn.disconnect()
            return True
        except Exception as e:
            import traceback
            print(f"[SSH ACL ERROR] Failed to apply SSH allow for {target_cidr}: {e}")
            print(f"[SSH ACL ERROR] Traceback: {traceback.format_exc()}")
            return False

    def _remove_ssh_allow(self, target_cidr: str) -> None:
        if ConnectHandler is None:
            return
        acl_name = 'MANUAL_ALLOWLIST'
        network_address = target_cidr.split('/')[0]
        commands = [
            'configure terminal',
            f'ip access-list extended {acl_name}',
            f'no permit ip host {network_address} any',
            f'no permit ip any host {network_address}',
            'exit',
            'write memory'
        ]
        try:
            conn = self._connect_ssh()
            conn.send_config_set(commands)
            conn.disconnect()
        except Exception as e:
            print(f"[SSH ACL ERROR] Failed to remove SSH allow for {target_cidr}: {e}")

    def _remove_ssh_block(self, target_cidr: str, origin: str = CALLER_AI) -> bool:
        """Removes an ACL on the switch via SSH using netmiko."""
        if ConnectHandler is None:
            print("[SSH ACL] netmiko not available in this environment.")
            return False

        acl_name = self._ssh_acl_name(target_cidr, origin)
        print(f"[SSH ACL] Removing block rule for {target_cidr} with ACL name {acl_name}")

        commands = [
            'configure terminal',
            f'interface {self.block_interface}',
            f'no ip access-group {acl_name} in',
            'exit',
            f'no ip access-list extended {acl_name}',
            'write memory'
        ]

        try:
            conn = self._connect_ssh()
            conn.send_config_set(commands)
            print(f"[SSH ACL] Successfully removed block rule for {target_cidr}")
            conn.disconnect()
            return True
        except Exception as e:
            import traceback
            print(f"[SSH ACL ERROR] Failed to remove SSH block for {target_cidr}: {e}")
            print(f"[SSH ACL ERROR] Traceback: {traceback.format_exc()}")
            return False

    def _remove_rule(self, target_cidr: str, caller: str = CALLER_AI):
        """
        Removes an active rule. Manual-origin entries are immune to AI/TTL/analyst
        callers — only caller=CALLER_MANUAL can evict a manual rule. Caller MUST
        hold self.lock; external IO (iptables/SSH delete) happens inside this call.
        """
        if '/' not in target_cidr and target_cidr not in self.active_rules:
            target_cidr = f"{target_cidr}/32"

        rule_data = self.active_rules.get(target_cidr, {})
        rule_origin = rule_data.get('origin', CALLER_AI)

        if rule_origin == CALLER_MANUAL and caller != CALLER_MANUAL:
            return False

        self._cleanup_external(target_cidr, rule_data)

        if target_cidr in self.active_rules:
            del self.active_rules[target_cidr]
        return True

    def _cleanup_external(self, target_cidr: str, rule_data: dict) -> None:
        """Issues the iptables/SSH/RESTCONF delete for a rule. No state mutation."""
        rule_type = rule_data.get('type', 'block')
        rule_origin = rule_data.get('origin', CALLER_AI)
        clean_ip = target_cidr.split('/')[0]

        if self.mode == "simulation":
            if rule_type == 'allow':
                self._remove_iptables_allow(target_cidr)
            elif rule_type == 'block':
                source_cmd = f"iptables -D INPUT -s {target_cidr} -j DROP"
                destination_cmd = f"iptables -D OUTPUT -d {target_cidr} -j DROP"
                subprocess.run(source_cmd.split(), check=False)
                subprocess.run(destination_cmd.split(), check=False)
            else:
                limit_name = f"throttle_{clean_ip.replace('.', '_')}"
                cmd = (
                    f"iptables -D INPUT -s {clean_ip} -m hashlimit --hashlimit-above 50/sec "
                    f"--hashlimit-burst 100 --hashlimit-mode srcip --hashlimit-name {limit_name} -j DROP"
                )
                subprocess.run(cmd.split(), check=False)
        elif self.mode == "hardware":
            if rule_type == 'allow':
                try:
                    self._remove_ssh_allow(target_cidr)
                except Exception:
                    pass
            elif rule_type == 'block':
                try:
                    removed = self._remove_ssh_block(target_cidr, origin=rule_origin)
                    if not removed:
                        acl_name = self._ssh_acl_name(target_cidr, rule_origin)
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

    def _fetch_switch_acl_rules(self):
        """
        Reads `show ip access-list` from the switch and returns a flat list of
        deny-host entries with their ACL names:

            [{'acl_name': str, 'ip_address': str}, ...]

        Returns None on SSH failure. Caller filters by ACL prefix.
        """
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

        entries = []
        current_acl_name = None
        seen_ips = set()

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            acl_match = re.match(r'^(Extended IP access list|IP access list extended)\s+(\S+)', line, re.IGNORECASE)
            if acl_match:
                current_acl_name = acl_match.group(2)
                seen_ips.clear()
                continue

            if not current_acl_name:
                continue

            if re.match(r'^\d+:\s*deny ip', line, re.IGNORECASE):
                host_match = re.search(r'deny ip host ([0-9.]+) any', line, re.IGNORECASE)
                if not host_match:
                    host_match = re.search(r'deny ip any host ([0-9.]+)', line, re.IGNORECASE)

                if host_match:
                    ip_address = host_match.group(1)
                    if ip_address not in seen_ips:
                        seen_ips.add(ip_address)
                        entries.append({'acl_name': current_acl_name, 'ip_address': ip_address})

        return entries

    def list_switch_block_rules(self):
        """
        Return manual-owned block rules currently configured on the switch
        (ACL names with prefix MAN_BLOCK_). AI-owned ACLs are excluded so they
        don't get laundered into the manual_firewall_rules table by the importer.
        """
        entries = self._fetch_switch_acl_rules()
        if entries is None:
            return None

        rules = []
        for entry in entries:
            acl_name = entry['acl_name']
            if not acl_name.startswith(ACL_PREFIX_MANUAL_BLOCK):
                continue
            rules.append({
                'ip_address': entry['ip_address'],
                'action': 'BLOCK',
                'rule_type': 'PERMANENT',
                'port': None,
                'notes': f"Imported from switch ACL {acl_name}",
                'status': 'ACTIVE',
                'acl_name': acl_name,
            })
        return rules

    def rehydrate_from_switch(self, default_ttl_seconds: int = 600) -> int:
        """
        On agent startup, read AI-owned ACLs (prefix AI_BLOCK_) already on the
        switch and repopulate self.active_rules so the dashboard reflects current
        enforcement. Returns the number of AI rules rehydrated.

        Each rehydrated entry gets `default_ttl_seconds` of fresh TTL so the
        normal GC continues to apply after restart.
        """
        if self.mode != "hardware":
            return 0

        entries = self._fetch_switch_acl_rules()
        if entries is None:
            return 0

        rehydrated = 0
        expiration = time.time() + default_ttl_seconds

        with self.lock:
            for entry in entries:
                acl_name = entry['acl_name']
                ip_address = entry['ip_address']
                if not acl_name.startswith(ACL_PREFIX_AI_BLOCK):
                    continue

                cidr = self._normalize_cidr(ip_address)
                # Don't clobber anything already tracked (e.g. manual rule for the same IP).
                if cidr in self.active_rules:
                    continue

                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                except ValueError:
                    continue

                self.active_rules[cidr] = {
                    'expiration': expiration,
                    'rule_id': acl_name,
                    'type': 'block',
                    'verdict': 'block',
                    'origin': CALLER_AI,
                    'network': network,
                    'port': None,
                }
                rehydrated += 1

        return rehydrated

    def _enforce_ttl(self):
        """Garbage collection for expired AI rules. Manual rules never expire here."""
        while True:
            time.sleep(10)
            current_time = time.time()

            # Snapshot + evict from dict under the lock; do external IO outside.
            with self.lock:
                expired = []
                for cidr, data in self.active_rules.items():
                    if data.get('origin') == CALLER_MANUAL:
                        continue
                    if data.get('expiration', math.inf) == math.inf:
                        continue
                    if current_time > data['expiration']:
                        expired.append((cidr, dict(data)))
                for cidr, _ in expired:
                    del self.active_rules[cidr]

            for cidr, data in expired:
                self._cleanup_external(cidr, data)

    def deploy_rate_limit_rule(self, target_ip: str, max_packets_per_second: int = 50, duration_seconds: int = 300, origin: str = CALLER_AI):
        """
        Deploys a rate-limiting rule. AI-origin deploys are skipped if the target
        overlaps any manual rule.
        """
        clean_ip = target_ip.split('/')[0]

        with self.lock:
            if origin == CALLER_AI:
                protected = self._is_protected_nolock(clean_ip)
                if protected is not None:
                    return False, "BLOCKED_BY_MANUAL_RULE", protected

            existing = self.active_rules.get(clean_ip)
            if existing is not None:
                if existing.get('origin') == CALLER_MANUAL:
                    return False, "CONFLICTS_WITH_MANUAL_RULE", existing
                # Extend AI throttle TTL.
                existing['expiration'] = max(existing['expiration'], time.time() + duration_seconds)
                return False, "Rule redundant. TTL extended.", None

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
                    'verdict': 'throttle',
                    'origin': origin,
                    'network': ipaddress.ip_network(f"{clean_ip}/32", strict=False),
                    'port': None,
                }
                return True, f"Bandwidth throttled to {max_packets_per_second} pps.", None

            return False, "Rate limit deployment failed.", None

    def _apply_iptables_throttle(self, target_ip: str, limit: int) -> bool:
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
