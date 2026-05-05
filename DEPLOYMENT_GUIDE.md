# Deployment Guide

This guide covers the Ruckus ICX 7150 setup for the RL firewall project with mirrored packet capture on the Docker host and SSH key-based ACL enforcement from the agent container.

## Physical topology

Your described layout is:

- Port 1: upstream Internet
- Port 2: client/PC traffic
- Port 3: client/PC traffic
- Port 12: mirror destination to the server NIC on `eno4`
- Management port: server NIC on `eno3`

The intended flow is:

1. Traffic enters and exits the switch normally on the data ports.
2. The switch mirrors selected traffic to port 12.
3. The Docker host receives the mirrored frames on `eno4`.
4. The agent inspects mirrored traffic and decides whether to block.
5. The agent pushes a FastIron ACL back to the switch over SSH.

## SSH key-based access

Use an SSH key for the agent container instead of a password when possible.

### 1. Create a key pair on the Docker host

```bash
ssh-keygen -t ed25519 -f ~/.ssh/icx_rl_firewall -C "rl-firewall"
```

If the switch only accepts older algorithms for the session setup, keep the key modern but continue using the legacy KEX flags for compatibility when testing from the host.

### 2. Copy the public key to the switch

Log in to the ICX 7150 and add the public key to the admin account or the device's SSH key store, depending on the FastIron firmware options available on your unit.

If the switch does not support direct key import through the current CLI, keep password auth as the fallback and use the key mount only when the switch accepts it.

### 3. Mount the private key into the agent container

The compose file mounts the host directory:

```text
./agent/secrets -> /run/secrets
```

Place the private key at:

```text
./agent/secrets/icx_rl_firewall
```

If you generated a different filename, update `ICX_KEY_FILE` and keep the mount path consistent.

### 4. Configure environment variables

The agent reads:

- `FIREWALL_MODE=hardware`
- `CAPTURE_IFACE=eno4`
- `ICX_MGMT_IP=192.168.1.50`
- `ICX_USER=admin`
- `ICX_PASSWORD=adminadmin`
- `ICX_KEY_FILE=/run/secrets/icx_rl_firewall`
- `ICX_KEY_PASSPHRASE=`

If `ICX_KEY_FILE` is present, `RuleManager` uses key-based SSH. If not, it falls back to the password.

## FastIron ACL and mirror configuration

The switch CLI should use FastIron commands, not Cisco syntax.

### Mirror the traffic

Adjust the port ranges to match your deployment.

```text
configure terminal
mirror session 1 source ethernet 1/1/1-1/1/3 both
mirror session 1 destination ethernet 1/1/12
exit
write memory
```

This mirrors traffic from ports 1 through 3 to port 12, which should connect to the server NIC on `eno4`.

### Verify the mirror session

```text
show mirror session 1
```

### Apply the ACL used by the agent

The agent creates per-target ACLs such as `BLOCK192168110032`. The exact command is built automatically by `RuleManager`, but the underlying FastIron style is:

```text
configure terminal
ip access-list extended BLOCK192168110032
deny ip host 192.168.1.100 any
exit
write memory
```

### Remove a block

When the rule TTL expires, the agent issues the reverse operation:

```text
configure terminal
no ip access-list extended BLOCK192168110032
write memory
```

## Docker runtime

Bring the agent up after updating the compose file:

```bash
docker compose up -d --build agent
```

If you are using the older CLI, this is equivalent to:

```bash
docker-compose up -d --build agent
```

## Validation checklist

1. `tcpdump -i eno4` shows mirrored packets when traffic is present on ports 1 to 3.
2. The agent container can reach `192.168.1.50` over SSH.
3. A test block causes `show access-list` on the switch to show a generated `BLOCK...` ACL.
4. The blocked host loses connectivity once the ACL is active.
5. Expired rules are removed automatically by the agent TTL cleanup thread.

## Operational notes

- Keep management traffic isolated on `eno3`.
- Use `eno4` only for mirrored inspection traffic.
- If the switch firmware does not allow key import, keep password fallback enabled until you can migrate the management account.
- Rotate the SSH key if the Docker host is rebuilt or the key is exposed.
