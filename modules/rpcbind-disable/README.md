# rpcbind-disable

Masks `rpcbind` (the SunRPC portmapper on TCP/UDP 111)
and the rpc statd/gssd helpers on hosts that don't use
NFSv3 / NIS / rquota. Removes a network-facing service-
locator that is a known DDoS reflection-amplification
vector and CVE target.

## Why this matters

`rpcbind` (formerly `portmap`) maps RPC program numbers
to network ports. It listens on TCP+UDP 111 and answers
"which port is service X on?" queries. It's needed ONLY
by RPC-based services: NFSv3, NIS/YP, rquotad, rpc.statd
(NFS lock manager).

Problems when it runs unnecessarily:

- **Reflection-amplification DDoS**: UDP 111 responders
  can be abused to amplify spoofed-source traffic. The
  "rpcbomb" (CVE-2017-8779) lets an attacker exhaust
  memory via crafted requests, and the portmap protocol
  is on every DDoS-reflector amplification list.
- **Reconnaissance**: `rpcinfo -p <host>` enumerates
  every RPC service + port — a map of the host's
  RPC attack surface.
- **NFSv4 doesn't need it**: NFSv4 uses a single
  well-known port (2049) + has no portmapper dependency.
  Hosts running NFSv4-only exports can mask rpcbind
  safely.

Most modern hosts run no RPC services at all. Masking
rpcbind closes port 111 entirely.

## Profiles

| Profile | Effect |
|---|---|
| `mask` (default) | stop + disable + mask rpcbind.service + rpcbind.socket + rpc-statd + rpc-statd-notify + rpc-gssd. Defeats socket re-activation. |
| `stop` | stop + disable only. |

apply.sh probes for unit existence — no-op on hosts
without rpcbind. It also WARNS (not fails) if
`nfs-server.service` is active, since masking rpcbind
breaks NFSv3 exports (NFSv4-only exports are unaffected).

## When NOT to use

- **NFSv3 server or client** — needs rpcbind + rpc.statd
  for the lock manager. Skip, or migrate to NFSv4 first.
- **NIS / YP domain members** — `ypbind` needs rpcbind.
- **rquota / quota-over-NFS** — needs rpcbind.

## MITRE coverage

- **T1498.002** Network Denial of Service: Reflection
  Amplification — PRIMARY; port-111 portmap is a classic
  reflector. Masking removes the host as a reflector.
- **T1046** Network Service Scanning — `rpcinfo -p`
  enumeration of RPC services denied.
- **T1190** Exploit Public-Facing Application — rpcbind
  CVE chain (CVE-2017-8779 rpcbomb) removed.
- **T1499** Endpoint Denial of Service — rpcbomb memory
  exhaustion removed.

## Operator workflow

```bash
# Verify port 111 is closed
ss -lntu | grep ':111 '          # expect: empty
systemctl status rpcbind 2>/dev/null | grep -E 'Loaded:|Active:'

# Confirm no RPC services advertised
rpcinfo -p localhost 2>&1 || echo "rpcbind not answering (good)"

# Re-enable for NFSv3 (operator decision)
sudo systemctl unmask rpcbind rpcbind.socket rpc-statd
sudo systemctl enable --now rpcbind
sudo systemctl restart nfs-server   # if NFSv3 server
```

## Caveats

- **NFSv3 breakage**: masking rpcbind while an NFSv3
  server is exporting WILL break mounts + locking.
  apply.sh warns. Migrate to NFSv4-only first, or skip
  this module.
- **NFS client (v3)**: an NFSv3 client also needs
  rpc.statd (lock recovery). NFSv4 clients do not.
- **Package upgrade may re-enable** without mask profile
  (socket activation on incoming port-111 traffic).
- **Container hosts**: rpcbind is host-scope. Containers
  mounting NFS typically use the host's NFS client.

## Coexistence

- **avahi-disable + nscd-disable + services-disable-
  printing + bluetooth-disable + apport-disable**: same
  service-mask family; orthogonal scopes. avahi (mDNS) +
  rpcbind (portmap) are the two classic LAN-facing
  reflection-amplification daemons — masking both shrinks
  the DDoS-reflector surface.
- **sysctl-network-baseline**: complementary IP-layer
  hardening (rp_filter, syncookies); rpcbind-disable
  removes a whole service.
- **fail2ban-bridge**: orthogonal; one fewer network
  daemon to monitor.
- **rare-network-protocols-disable**: complementary —
  that blocks rare protocol KERNEL modules; this masks
  a userspace RPC daemon.
