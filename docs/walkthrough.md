# Walkthrough

Section-by-section commentary on what `harden.sh` does and why. Useful when you want to apply the playbook piecemeal or audit a specific change.

## 1. SSH hardening

```text
PermitRootLogin   prohibit-password
PasswordAuthentication no
MaxAuthTries      4
LoginGraceTime    60
ClientAliveInterval 300 / Count 0   # 5-minute idle timeout
```

Why `prohibit-password` rather than `no`? Proxmox clusters use root over SSH (`pveupdaterunner`, live migration, replication). Disabling root entirely breaks clustering. Restricting it to **public-key-only** is the right middle ground.

Cipher / KEX / MAC are restricted to modern primitives. Strict modes (`PasswordAuthentication no`, `MaxAuthTries 4`) are CIS standards.

## 2. fail2ban

The default Debian `fail2ban` package now drives off `systemd` journal, which is the recommended backend on PVE. The default 10 min ban after 5 failures is a sensible starting point.

## 3. sysctl

Network-side: redirect handling, SYN cookies, reverse-path filter, log martians, broadcast ignore. Standard server hygiene.

`ip_forward = 1` is required: a Proxmox host routes packets between VM bridges.

`fs.suid_dumpable = 0` prevents SUID binaries from generating core dumps. Combined with `* hard core 0` in section 4, this kills the entire core-dump attack surface.

IPv6 is disabled by default in the script. If you use IPv6 (some networks do), comment out the two lines. The CIS Debian benchmark accepts both states as long as the **decision is explicit**.

## 4. Filesystem hardening

`/dev/shm noexec,nosuid,nodev`: removes a classic privilege-escalation playground. Some niche software (Postgres parallel workers, sshfs caches) used to rely on it; the modern Debian default tolerates it well.

Cron directory permissions: `chmod 600 /etc/crontab` and `chmod 700 /etc/cron.{d,daily,hourly,weekly,monthly}`. This is straight from the CIS benchmark.

Core dumps: `* hard core 0` blocks user-process cores. Combined with `fs.suid_dumpable = 0` (section 3), nothing should land in `/var/lib/systemd/coredump` again.

## 5. Kernel module blacklist

Two categories:

- **Unused protocols** (`dccp`, `sctp`, `rds`, `tipc`): historical CVE magnets, no use on a typical Proxmox host.
- **Unused filesystems** (`cramfs`, `freevxfs`, `jffs2`, `hfs`, `hfsplus`, `squashfs`, `udf`): never mounted on a server; loading the modules expands the kernel attack surface.

USB storage (`usb-storage`, `uas`) is in a separate file so you can comment it out if you need USB-disk attach (e.g. local PBS bootstrap). When commented, run `update-initramfs -u && reboot` for it to take effect.

## 6. PAM password quality

`minlen = 12` plus at least one of each character class. Trivial to tighten further (`minclass = 4`, `dcredit -1`) if your security team requires.

This only applies to **password-set events** (`passwd`, `chpasswd`), not to existing hashes. Force a password change for any non-compliant local account.

## 7. Miscellaneous CIS items

- `UMASK 027` in `/etc/login.defs`: new files default to `640`, new dirs to `750`.
- Persistent journald (`/var/log/journal`): keeps logs across reboots, much easier post-mortem than relying on syslog forwarding.

## 8. Proxmox-specific

`spiceproxy` and `ksmtuned`:

- `spiceproxy` is the SPICE-console gateway. Disable it if you never connect to VMs via SPICE (you probably don't).
- `ksmtuned` is the kernel-managed KSM auto-tuner. It uses aggressive heuristics. We disable it and replace it with a fixed scan interval in section 9.

`pve-no-subscription`: enables apt updates without a Proxmox subscription. If you do have a subscription, skip this step (or revert manually).

The repo file uses the running Debian codename (`bookworm` for PVE 8.0-8.3, `trixie` for PVE 8.4+).

## 9. Memory tuning

`vm.swappiness = 10`: with 100+ GB of RAM, the default `swappiness=60` swaps out idle pages aggressively. On a hypervisor running large Windows VMs, this causes I/O latency spikes for no benefit: pages have to be paged back in as soon as the VM touches them. `10` keeps the kernel honest without disabling swap entirely.

KSM (`Kernel Same-page Merging`): identical memory pages across VMs are merged into a single physical page. Particularly effective for Windows VMs sharing the same kernel, DLLs, .NET runtime. Can recover several GB on a host with 3+ Windows Server VMs.

Why a systemd one-shot instead of sysctl? `/sys/kernel/mm/ksm/run` is exposed via `sysfs`, not `proc`, so `sysctl` cannot set it directly. The one-shot service writes the file at every boot.

Tuning parameters:

- `run = 1`: enable.
- `sleep_millisecs = 200`: scan every 200 ms. Lower = more aggressive dedupe, higher CPU. 200 is a good middle ground.

## 10. rpcbind via tcpwrappers

`rpcbind` must stay running: it's required for NFS client mounts, which most production Proxmox clusters use for backup storage or ISO repositories. CIS would prefer it disabled; we restrict it instead.

Default rules in this playbook accept RFC1918 ranges. **Tighten to your actual subnet** in production:

```ini
rpcbind: 127.0.0.1, 10.20.30.0/255.255.255.0
```

## Manual follow-up

The script logs these at the end; they need a human.

### Two-factor auth on PVE accounts

In the web UI: Datacenter -> Permissions -> Two Factor -> Add -> TOTP. Apply to every admin user (`root@pam` and your dedicated admin).

### Monitoring agents

Whatever stack you use:

- Wazuh agent for FIM and intrusion detection
- Promtail + Loki for log shipping
- node_exporter (port 9100) for Prometheus

### Backup

Proxmox Backup Server (PBS) is the obvious choice. Schedule daily snapshots of every VM / CT.

### Reboot

After the playbook runs, reboot the host to make sure every kernel-level change (sysctl, blacklisted modules, journald) is loaded fresh.
