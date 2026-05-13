#!/usr/bin/env bash
#
# Proxmox VE host hardening playbook
# https://github.com/fawraw/proxmox-host-hardening
#
# Idempotent: safe to re-run. Backups under /root/hardening-backups/<ts>/.
# Use --dry-run to see what would change without applying.

set -euo pipefail

DRY_RUN=0
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        --help|-h)
            sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "Unknown argument: $arg" >&2; exit 2 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "Run as root or with sudo." >&2
    exit 1
fi

TS=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="/root/hardening-backups/${TS}"
mkdir -p "${BACKUP_DIR}"

log()   { printf '[\033[1;34m HRDN \033[0m] %s\n' "$*"; }
apply() {
    if [[ $DRY_RUN -eq 1 ]]; then
        printf '[\033[1;33m DRY  \033[0m] %s\n' "$*"
    else
        eval "$@"
    fi
}
backup_file() {
    local f="$1"
    [[ -f "$f" ]] && cp -a "$f" "${BACKUP_DIR}/$(basename "$f").orig" || true
}

# ---------- 1. SSH hardening ----------------------------------------------------
harden_ssh() {
    log "SSH hardening"
    backup_file /etc/ssh/sshd_config.d/hardening.conf
    apply "tee /etc/ssh/sshd_config.d/hardening.conf > /dev/null <<'EOF'
# Authentication
PermitRootLogin prohibit-password
PasswordAuthentication no
MaxAuthTries 4
LoginGraceTime 60
X11Forwarding no

# Session timeout (5 min idle)
ClientAliveInterval 300
ClientAliveCountMax 0

# Strong ciphers / KEX only
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org

# Banner
Banner /etc/issue.net
EOF"
    apply "echo 'Authorized access only. All activity is monitored and logged.' > /etc/issue.net"
    apply "systemctl restart ssh"
}

# ---------- 2. fail2ban --------------------------------------------------------
install_fail2ban() {
    log "fail2ban with systemd backend"
    apply "apt-get install -y fail2ban"
    backup_file /etc/fail2ban/jail.local
    apply "tee /etc/fail2ban/jail.local > /dev/null <<'EOF'
[sshd]
enabled = true
backend = systemd
EOF"
    apply "systemctl enable --now fail2ban"
}

# ---------- 3. sysctl ----------------------------------------------------------
sysctl_hardening() {
    log "sysctl hardening"
    backup_file /etc/sysctl.d/99-hardening.conf
    apply "tee /etc/sysctl.d/99-hardening.conf > /dev/null <<'EOF'
# Reject ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Common hardening
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Disable IPv6 if not used (comment out if you use IPv6)
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# IP forwarding required for VMs
net.ipv4.ip_forward = 1

# Disable core dumps via suid binaries
fs.suid_dumpable = 0
EOF"
    apply "sysctl --system"
}

# ---------- 4. Filesystem ------------------------------------------------------
fs_hardening() {
    log "Filesystem (/dev/shm, cron perms, core dumps)"
    if ! grep -qE '^[^#]*\s/dev/shm\s' /etc/fstab; then
        backup_file /etc/fstab
        apply "echo 'tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0' >> /etc/fstab"
        apply "mount -o remount /dev/shm || true"
    fi
    apply "chmod 600 /etc/crontab"
    apply "chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly"

    if ! grep -q '^\* hard core 0' /etc/security/limits.conf; then
        backup_file /etc/security/limits.conf
        apply "echo '* hard core 0' >> /etc/security/limits.conf"
    fi
}

# ---------- 5. Kernel module blacklist -----------------------------------------
blacklist_modules() {
    log "Kernel module blacklist (unused FS / protocols)"
    backup_file /etc/modprobe.d/hardening-blacklist.conf
    apply "tee /etc/modprobe.d/hardening-blacklist.conf > /dev/null <<'EOF'
# Unused network protocols
blacklist dccp
blacklist sctp
blacklist rds
blacklist tipc

# Unused filesystems on a server
blacklist cramfs
blacklist freevxfs
blacklist jffs2
blacklist hfs
blacklist hfsplus
blacklist squashfs
blacklist udf

# Firewire
blacklist firewire-core
blacklist firewire-ohci
EOF"

    # USB storage: comment out if you need USB-disk attach on the host
    backup_file /etc/modprobe.d/usb-storage-blacklist.conf
    apply "tee /etc/modprobe.d/usb-storage-blacklist.conf > /dev/null <<'EOF'
blacklist usb-storage
blacklist uas
EOF"
}

# ---------- 6. PAM password quality --------------------------------------------
pam_quality() {
    log "PAM password quality"
    apply "apt-get install -y libpam-pwquality"
    backup_file /etc/security/pwquality.conf
    apply "tee /etc/security/pwquality.conf > /dev/null <<'EOF'
minlen = 12
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
EOF"
}

# ---------- 7. Misc CIS items --------------------------------------------------
misc_cis() {
    log "umask, journald, login.defs"
    backup_file /etc/login.defs
    apply "sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs"

    apply "mkdir -p /var/log/journal"
    apply "sed -i 's/^#\\?Storage=auto/Storage=persistent/' /etc/systemd/journald.conf"
    apply "systemctl restart systemd-journald"
}

# ---------- 8. Proxmox-specific ------------------------------------------------
pve_specific() {
    log "Proxmox: disable spiceproxy + ksmtuned, enable no-subscription repo"
    apply "systemctl disable --now spiceproxy 2>/dev/null || true"
    apply "systemctl disable --now ksmtuned   2>/dev/null || true"

    # Enable no-subscription repo (idempotent)
    if [[ -f /etc/apt/sources.list.d/pve-enterprise.sources ]]; then
        apply "mv /etc/apt/sources.list.d/pve-enterprise.sources /etc/apt/sources.list.d/pve-enterprise.sources.disabled"
    fi
    if [[ -f /etc/apt/sources.list.d/ceph.sources ]]; then
        apply "mv /etc/apt/sources.list.d/ceph.sources /etc/apt/sources.list.d/ceph.sources.disabled"
    fi
    if [[ ! -f /etc/apt/sources.list.d/pve-no-subscription.list ]]; then
        # Detect Debian codename (bookworm/trixie) and pick the matching PVE repo
        codename=$(. /etc/os-release && echo "$VERSION_CODENAME")
        apply "echo 'deb http://download.proxmox.com/debian/pve ${codename} pve-no-subscription' > /etc/apt/sources.list.d/pve-no-subscription.list"
        apply "apt-get update"
    fi
}

# ---------- 9. Memory tuning ---------------------------------------------------
memory_tuning() {
    log "Hypervisor memory tuning (swappiness, KSM)"
    backup_file /etc/sysctl.d/99-hypervisor-tuning.conf
    apply "tee /etc/sysctl.d/99-hypervisor-tuning.conf > /dev/null <<'EOF'
# Reduce proactive swapping. With ample RAM the default (60) swaps too aggressively.
vm.swappiness = 10
EOF"
    apply "sysctl --system"

    # KSM via systemd one-shot (the file under /sys is not sysctl-controllable)
    backup_file /etc/systemd/system/ksm-tuning.service
    apply "tee /etc/systemd/system/ksm-tuning.service > /dev/null <<'EOF'
[Unit]
Description=Enable KSM memory deduplication
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'echo 1 > /sys/kernel/mm/ksm/run && echo 200 > /sys/kernel/mm/ksm/sleep_millisecs'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF"
    apply "systemctl daemon-reload"
    apply "systemctl enable --now ksm-tuning.service"
}

# ---------- 10. rpcbind tcpwrappers --------------------------------------------
rpcbind_restrict() {
    log "Restrict rpcbind (required by NFS client)"
    if ! grep -q '^rpcbind:' /etc/hosts.allow 2>/dev/null; then
        backup_file /etc/hosts.allow
        # Default: allow only localhost + RFC1918 ranges. Tighten further to match your subnet.
        apply "tee -a /etc/hosts.allow > /dev/null <<'EOF'
rpcbind: 127.0.0.1, 10.0.0.0/255.0.0.0, 172.16.0.0/255.240.0.0, 192.168.0.0/255.255.0.0
EOF"
    fi
    if ! grep -q '^rpcbind: ALL' /etc/hosts.deny 2>/dev/null; then
        backup_file /etc/hosts.deny
        apply "echo 'rpcbind: ALL' >> /etc/hosts.deny"
    fi
}

# ---------- main ---------------------------------------------------------------
log "Backups will be written to ${BACKUP_DIR}"
harden_ssh
install_fail2ban
sysctl_hardening
fs_hardening
blacklist_modules
pam_quality
misc_cis
pve_specific
memory_tuning
rpcbind_restrict

log "Done. Recommended manual follow-up:"
cat <<'EOF'

  1. Enable two-factor auth on PVE accounts (GUI: Datacenter > Permissions > Two Factor).
  2. Deploy your monitoring agents (Wazuh, Promtail, node_exporter).
  3. Add the host to your backup schedule (PBS).
  4. Reboot to make sure all kernel-level changes (sysctl, modules, journald) take effect.

EOF
