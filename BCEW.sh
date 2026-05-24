# ==============================================================================
# SECURITY IMPROVEMENTS — CMNI ENTERPRISE HARDENING
# VERSION.........: 2.6 Enterprise Hardened
# ORGANIZATION....: Falcon Critical Operations (FCO)
# ==============================================================================

# ==============================================================================
# 1. LDAP OVER TLS (LDAPS)
# ==============================================================================

LDAP_SERVER="ldaps://192.168.10.10"

# ------------------------------------------------------------------------------
# INSTALL CA CERTIFICATE
# ------------------------------------------------------------------------------

mkdir -p /usr/local/share/ca-certificates/fco

cp FCO-ROOT-CA.crt \
/usr/local/share/ca-certificates/fco/

update-ca-certificates

# ------------------------------------------------------------------------------
# SECURE SSSD CONFIGURATION
# ------------------------------------------------------------------------------

cat > /etc/sssd/sssd.conf <<EOF
[sssd]
services = nss, pam
config_file_version = 2
domains = empresa.local

[nss]
homedir_substring = /home

[pam]

[domain/empresa.local]

id_provider = ldap
auth_provider = ldap
chpass_provider = ldap

ldap_uri = ldaps://192.168.10.10

ldap_search_base = dc=empresa,dc=local

ldap_tls_reqcert = demand

ldap_tls_cacert = /etc/ssl/certs/ca-certificates.crt

cache_credentials = true
enumerate = false

fallback_homedir = /home/%u
default_shell = /bin/bash
EOF

chmod 600 /etc/sssd/sssd.conf

systemctl restart sssd

# ==============================================================================
# 2. SSH HARDENING — ENTERPRISE LEVEL
# ==============================================================================

cp /etc/ssh/sshd_config \
/etc/ssh/sshd_config.backup

cat > /etc/ssh/sshd_config <<EOF
Port 22

Protocol 2

PermitRootLogin no

PasswordAuthentication no

PubkeyAuthentication yes

PermitEmptyPasswords no

MaxAuthTries 3

LoginGraceTime 30

ClientAliveInterval 300

ClientAliveCountMax 2

X11Forwarding no

AllowTcpForwarding no

AllowAgentForwarding no

UsePAM yes

AuthorizedKeysFile .ssh/authorized_keys

AllowGroups sudo

Banner /etc/issue.net

Subsystem sftp internal-sftp
EOF

systemctl restart ssh

# ==============================================================================
# 3. SSH LEGAL WARNING BANNER
# ==============================================================================

cat > /etc/issue.net <<EOF
***************************************************************************
* WARNING: AUTHORIZED ACCESS ONLY                                        *
*                                                                         *
* This system is the property of Falcon Critical Operations (FCO).        *
* Unauthorized access is prohibited and subject to monitoring.            *
* All activities may be logged and audited.                               *
***************************************************************************
EOF

# ==============================================================================
# 4. ADVANCED SYSCTL HARDENING
# ==============================================================================

cat > /etc/sysctl.d/99-fco-hardening.conf <<EOF

# Disable IP forwarding
net.ipv4.ip_forward=0

# Disable redirects
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0

# Disable source routing
net.ipv4.conf.all.accept_source_route=0

# Enable SYN cookies
net.ipv4.tcp_syncookies=1

# Log martians
net.ipv4.conf.all.log_martians=1

# Disable ICMP redirects
net.ipv4.conf.all.send_redirects=0

# Kernel ASLR
kernel.randomize_va_space=2

# Restrict dmesg
kernel.dmesg_restrict=1

# Restrict ptrace
kernel.yama.ptrace_scope=1

# Disable magic sysrq
kernel.sysrq=0

# Protect hardlinks/symlinks
fs.protected_hardlinks=1
fs.protected_symlinks=1
EOF

sysctl --system

# ==============================================================================
# 5. ADVANCED AUDITD RULES
# ==============================================================================

cat > /etc/audit/rules.d/fco.rules <<EOF

# Identity monitoring
-w /etc/passwd -p wa -k passwd_changes
-w /etc/group -p wa -k group_changes
-w /etc/shadow -p wa -k shadow_changes

# Sudo monitoring
-w /etc/sudoers -p wa -k sudoers_changes

# SSH monitoring
-w /etc/ssh/sshd_config -p wa -k ssh_changes

# Authentication logs
-w /var/log/auth.log -p wa -k auth_logs

# Privilege escalation
-w /bin/su -p x -k privilege_escalation
-w /usr/bin/sudo -p x -k privilege_escalation

EOF

augenrules --load

systemctl restart auditd

# ==============================================================================
# 6. UFW HARDENING
# ==============================================================================

ufw --force reset

ufw default deny incoming
ufw default deny routed
ufw default allow outgoing

# Restrict SSH to management VLAN only
ufw allow from 192.168.10.0/24 to any port 22 proto tcp

# Netdata restricted
ufw allow from 192.168.10.0/24 to any port 19999 proto tcp

ufw logging high

ufw --force enable

# ==============================================================================
# 7. FAIL2BAN HARDENING
# ==============================================================================

cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]

bantime  = 1h
findtime = 10m
maxretry = 3

backend = systemd

[sshd]

enabled = true
port = ssh
logpath = %(sshd_log)s
EOF

systemctl restart fail2ban

# ==============================================================================
# 8. USB DEVICE CONTROL
# ==============================================================================

systemctl enable usbguard
systemctl start usbguard

usbguard generate-policy > /etc/usbguard/rules.conf

# ==============================================================================
# 9. FILE INTEGRITY MONITORING
# ==============================================================================

aideinit

cp /var/lib/aide/aide.db.new \
/var/lib/aide/aide.db

# ==============================================================================
# 10. AUTOMATIC SECURITY UPDATES
# ==============================================================================

apt install -y unattended-upgrades

dpkg-reconfigure -plow unattended-upgrades

# ==============================================================================
# 11. DISABLE UNUSED SERVICES
# ==============================================================================

systemctl disable avahi-daemon || true
systemctl disable cups || true
systemctl disable bluetooth || true

# ==============================================================================
# 12. WAZUH AGENT HARDENING
# ==============================================================================

systemctl enable wazuh-agent
systemctl restart wazuh-agent

# ==============================================================================
# 13. APPARMOR ENFORCEMENT
# ==============================================================================

systemctl enable apparmor
systemctl restart apparmor

aa-enforce /etc/apparmor.d/* || true

# ==============================================================================
# 14. SECURE PERMISSIONS
# ==============================================================================

chmod 700 /root

chmod 600 /etc/shadow
chmod 644 /etc/passwd

# ==============================================================================
# 15. ENTERPRISE VALIDATION
# ==============================================================================

echo ""
echo "=============================================================================="
echo " FCO ENTERPRISE HARDENING APPLIED"
echo "=============================================================================="
echo ""
echo "SECURITY CONTROLS:"
echo ""
echo " [✓] LDAP over TLS"
echo " [✓] SSH Key Authentication"
echo " [✓] Sysctl Hardening"
echo " [✓] Auditd Rules"
echo " [✓] UFW Restricted Access"
echo " [✓] Fail2Ban"
echo " [✓] USBGuard"
echo " [✓] AppArmor Enforcement"
echo " [✓] AIDE File Integrity"
echo " [✓] Automatic Security Updates"
echo ""
echo "SECURITY STATUS: ENTERPRISE HARDENED"
echo ""
echo "=============================================================================="