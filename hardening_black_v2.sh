#!/bin/bash
# ██╗  ██╗ █████╗ ██╗     ██╗ ██████╗ ██████╗ ███╗   ███╗
# ██║ ██╔╝██╔══██╗██║     ██║██╔═══██╗██╔══██╗████╗ ████║
# █████╔╝ ███████║██║     ██║██║   ██║██████╔╝██╔████╔██║
# ██╔═██╗ ██╔══██║██║     ██║██║   ██║██╔═══╝ ██║╚██╔╝██║
# ██║  ██╗██║  ██║███████╗██║╚██████╔╝██║     ██║ ╚═╝ ██║
# ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝ ╚═════╝ ╚═╝     ╚═╝     ╚═╝

set -euo pipefail
IFS=$'\n\t'
logfile="/var/log/kali-black-hardening.log"
exec > >(tee -a "$logfile") 2>&1

# Variáveis adaptáveis
# Certifique-se de que a porta definida esteja liberada nas regras de firewall em cloud (AWS SGs, Azure NSG, GCP FW)
SSH_PORT=${SSH_PORT:-2222}
SSH_USER=${SSH_USER:-cyberadmin}
DRY_RUN=${DRY_RUN:-false}

if [[ "$DRY_RUN" == "true" ]]; then
  echo "[DRY-RUN] Nenhuma alteração será aplicada."
  exit 0
fi

check_error() {
  if [[ $? -ne 0 ]]; then
    echo "[❌] ERRO detectado. Finalizando execuções por segurança." | tee -a /var/log/hardening-fail.log
    exit 1
  fi
}

# Atualizações e pacotes essenciais
apt update && apt full-upgrade -y && apt install unattended-upgrades apt-listchanges net-tools curl wget -y
check_error

# SSH endurecido
sed -i "s/^#Port.*/Port $SSH_PORT/" /etc/ssh/sshd_config
sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
echo "AllowUsers $SSH_USER" >> /etc/ssh/sshd_config
systemctl restart ssh

# Firewall nftables
apt install nftables -y
systemctl enable --now nftables
cat > /etc/nftables.conf <<EOF
table inet filter {
  chain input {
    type filter hook input priority 0;
    policy drop;
    iifname "lo" accept
    ct state established,related accept
    tcp dport $SSH_PORT accept
    ip protocol icmp icmp type echo-request limit rate 5/second accept
    log prefix "DROP " flags all counter drop
  }
}
EOF
nft -f /etc/nftables.conf

# GeoIP restrição (exemplo simplificado)
apt install xtables-addons-common libtext-csv-xs-perl libmoosex-types-netaddr-ip-perl libgeo-ip-perl -y
iptables -A INPUT -m geoip ! --src-cc BR,US -j DROP

# Fail2Ban
apt install fail2ban -y
cat > /etc/fail2ban/jail.d/sshd.conf <<EOF
[sshd]
enabled = true
port = $SSH_PORT
maxretry = 3
bantime = 3600
EOF
systemctl restart fail2ban

# Monitoramento com auditd e aide
apt install auditd audispd-plugins aide -y
cat > /etc/audit/rules.d/harden.rules <<EOF
-w /etc/passwd -p wa -k passwd
-w /etc/shadow -p wa -k shadow
-w /etc/ssh/sshd_config -p wa -k ssh
-w /usr/bin -p x -k execs
EOF
augenrules --load
aideinit && cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Honeypot SSH falso (cowrie)
apt install git python3-virtualenv -y
useradd -m -s /bin/bash cowrie
cat > /usr/local/bin/install-cowrie.sh <<'EOS'
#!/bin/bash
cd /home/cowrie || exit 1
sudo -u cowrie git clone https://github.com/cowrie/cowrie.git
cd cowrie || exit 1
sudo -u cowrie python3 -m venv cowrie-env
source cowrie-env/bin/activate
sudo -u cowrie pip install -r requirements.txt
sudo -u cowrie cp etc/cowrie.cfg.dist etc/cowrie.cfg
EOS
chmod +x /usr/local/bin/install-cowrie.sh
su - cowrie -c '/usr/local/bin/install-cowrie.sh'

# Criptografia reforçada no SSH
cat >> /etc/ssh/sshd_config <<EOF
KexAlgorithms curve25519-sha256
Ciphers chacha20-poly1305@openssh.com
MACs hmac-sha2-512-etm@openssh.com
EOF
systemctl restart ssh

# Kernel hardening
cat > /etc/sysctl.d/99-black-sec.conf <<EOF
net.ipv4.conf.all.rp_filter = 1
kernel.kptr_restrict = 2
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
EOF
sysctl --system

# Imutabilidade
chattr +i /etc/passwd /etc/shadow /etc/ssh/sshd_config

# Logging externo opcional
echo "*.* @@siem.yourdomain.com:514" >> /etc/rsyslog.d/99-siem.conf
systemctl restart rsyslog

# Geração de relatório (verificação de dependência pandoc)
if command -v pandoc >/dev/null 2>&1; then
  echo "## RELATÓRIO DE HARDENING $(date)" > /root/hardening-report.md
  echo "- Hostname: $(hostname)" >> /root/hardening-report.md
  echo "- SSH Porta: $SSH_PORT" >> /root/hardening-report.md
  pandoc /root/hardening-report.md -o /root/hardening-report.pdf
else
  echo "[⚠️] pandoc não está instalado. Relatório PDF não gerado."
fi

echo "[✅] HARDENING BLACK COMPLETO - AMBIENTE SEGURO E PRONTO."
echo "[📌] Log: $logfile"
