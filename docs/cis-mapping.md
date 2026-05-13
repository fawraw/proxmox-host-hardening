# CIS Debian / Proxmox mapping

Mapping of `harden.sh` sections to CIS Debian Linux benchmark controls. Use this to demonstrate coverage during an audit.

## Sections and CIS controls

| Section in `harden.sh` | CIS Debian control (representative) | Notes |
|------------------------|-------------------------------------|-------|
| `harden_ssh`           | 5.3.x (SSH server configuration)    | `PermitRootLogin prohibit-password` instead of `no`, see accepted-findings |
| `install_fail2ban`     | 5.2.x (Operating-system level intrusion detection) | systemd backend |
| `sysctl_hardening`     | 3.2.x, 3.3.x (Network parameters)   | IPv6 disabled by default; revert if you use it |
| `fs_hardening`         | 1.1.x (Filesystem configuration)    | `/dev/shm`, cron perms, core dumps |
| `blacklist_modules`    | 1.1.1.x (Disable unused filesystems), 3.4.x (Disable unused protocols) | USB-storage in separate file |
| `pam_quality`          | 5.4.x (PAM configuration)           | `minlen=12`, full class diversity |
| `misc_cis`             | 5.4.5 (default umask), 4.2.x (logging) | `UMASK 027`, persistent journald |
| `pve_specific`         | (Proxmox-specific)                  | Repo selection + disable unused services |
| `memory_tuning`        | (performance, not CIS)              | swappiness + KSM |
| `rpcbind_restrict`     | 2.2.4 (Disable rpcbind): ACCEPTED FINDING | required by NFS client |

## Coverage summary

The playbook addresses every CIS Debian section relevant to a server running as a hypervisor, with three documented deviations:

1. **SSH root login**: `prohibit-password` (key-only) instead of `no`, because the PVE cluster requires it.
2. **rpcbind**: restricted via tcpwrappers, not disabled, because NFS clients need it.
3. **auditd**: not installed. The host's audit story is covered by Wazuh FIM (file integrity monitoring) + syslog forwarding. CIS allows substitute solutions.

See [accepted-findings.md](accepted-findings.md) for the full justification.

## Not in scope of CIS

The Proxmox-specific sections (`pve_specific`, `memory_tuning`) are not in the CIS benchmark. They reflect production practice on a Proxmox cluster and are documented for completeness.
