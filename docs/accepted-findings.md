# Accepted findings

CIS controls that this playbook **deliberately does not enforce**, with the rationale. Use this document during an audit to explain why a clean CIS scan still shows a few findings.

| Finding                                 | Rationale                                                                      |
|------------------------------------------|--------------------------------------------------------------------------------|
| `PermitRootLogin` is `prohibit-password` and not `no` | Proxmox clusters use root SSH between nodes for live migration, replication, and `pveupdaterunner`. Key-only is the strongest setting that keeps clustering working. |
| `rpcbind` is running (restricted, not disabled) | NFS client mounts are the standard way to attach a backup target (PBS over NFS, NetApp, etc.). Restricted via tcpwrappers (`/etc/hosts.allow`, `/etc/hosts.deny`). |
| `auditd` is not installed                | Wazuh agent provides equivalent FIM and security event collection. CIS allows substitute solutions when functionally equivalent. |
| NFS mounts are not Kerberos-secured       | LAN is private and behind a perimeter firewall. Kerberos for NFSv4.1 / 4.2 is operationally heavy for a small cluster and rarely worth the complexity in a homogeneous Linux + NetApp environment. Revisit if the threat model includes east-west attackers. |
| `ClamAV` is not installed                | Server with no user-facing file ingress. The attack surface ClamAV protects against (email gateways, Samba file servers) is not present here. |
| IPv6 disabled by default                  | Many internal networks are still IPv4-only. The script does this explicitly; comment out the two `disable_ipv6` lines if your network has IPv6 routing. |
| USB-storage blacklisted                   | Threat model: prevent unauthorised data exfiltration via thumb drives at the console. Comment out if you need USB-disk attach (e.g. local PBS bootstrap). |

## How to revisit

These are decisions, not omissions. Re-audit them when:

- The cluster changes shape (more nodes, different storage backend, multi-tenant access).
- The compliance frame changes (a new auditor with stricter expectations).
- A new credible threat appears (e.g. east-west compromise from a tenant VM).

Each one should be a one-page memo, not a quick edit to this file.
