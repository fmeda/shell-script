#!/bin/bash
# SecureMilitaryHardening.sh 2025 - Hardening Militar Completo
# Autor: FABIANO MEDA | Versão: 3.5 | Data: 15-08-2025
# Licença: MIT

LOG_FILE="/var/log/military_hardening.log"

# ---------------- Funções Base ----------------
log_message() {
    local MESSAGE="$1"
    local LEVEL="${2:-INFO}"
    echo "{\"timestamp\":\"$(date '+%Y-%m-%d %H:%M:%S')\",\"level\":\"$LEVEL\",\"message\":\"$MESSAGE\"}" | tee -a "$LOG_FILE"
}

backup_file() {
    local FILE="$1"
    if [[ -f "$FILE" ]]; then
        cp "$FILE" "$FILE.bak_$(date '+%Y%m%d%H%M%S')"
        log_message "Backup criado para $FILE" "INFO"
    fi
}

check_command() {
    local CMD="$1"
    command -v "$CMD" >/dev/null 2>&1 || { log_message "Comando $CMD não encontrado. Abortando." "ERROR"; exit 1; }
}

install_packages() {
    local PACKAGES=("$@")
    for pkg in "${PACKAGES[@]}"; do
        dpkg -l | grep -qw "$pkg" || apt-get install -y "$pkg"
    done
}

# ---------------- FIREWALL ----------------
configure_firewall() {
    log_message "Configurando firewall iptables..." "INFO"
    check_command iptables
    iptables -F && iptables -X && iptables -Z
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -s 192.168.1.0/24 -j ACCEPT
    iptables -A INPUT -p tcp --match multiport --dports 23,2323,3389 -j DROP
    iptables-save > /etc/iptables/rules.v4
    log_message "Firewall iptables configurado." "SUCCESS"

    log_message "Configurando nftables..." "INFO"
    check_command nft
    cat <<EOF > /etc/nftables.conf
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
    chain input { type filter hook input priority 0; policy drop;
        ct state established,related accept
        iif "lo" accept
        tcp dport 22 accept
    }
    chain forward { type filter hook forward priority 0; policy drop; }
    chain output { type filter hook output priority 0; policy accept; }
}
EOF
    systemctl enable nftables && systemctl restart nftables
    log_message "Firewall nftables configurado." "SUCCESS"
}

# ---------------- HARDENING KERNEL ----------------
harden_kernel() {
    log_message "Aplicando hardening do kernel..." "INFO"
    backup_file /etc/sysctl.conf
    cat <<EOF >> /etc/sysctl.conf
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
kernel.randomize_va_space = 2
net.ipv4.conf.all.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
EOF
    sysctl -p
    log_message "Kernel hardened com sucesso." "SUCCESS"

    # Desabilitar módulos de kernel não utilizados
    backup_file /etc/modprobe.d/disable-filesystems.conf
    for fs in cramfs freevxfs jffs2 hfs hfsplus squashfs udf vfat; do
        echo "install $fs /bin/true" >> /etc/modprobe.d/disable-filesystems.conf
    done
    log_message "Módulos de kernel não utilizados desabilitados." "SUCCESS"
}

# ---------------- PAM ----------------
configure_pam() {
    log_message "Configurando PAM..." "INFO"
    backup_file /etc/pam.d/common-password
    backup_file /etc/pam.d/common-auth
    sed -i 's/^password\s*requisite\s*pam_pwquality.so.*/password requisite pam_pwquality.so retry=3 minlen=14 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password
    sed -i 's/^auth\s*required\s*pam_tally2.so.*/auth required pam_tally2.so deny=5 unlock_time=600/' /etc/pam.d/common-auth
    log_message "PAM configurado." "SUCCESS"
}

# ---------------- LDAP/KERBEROS ----------------
configure_authentication() {
    log_message "Configurando LDAP/Kerberos..." "INFO"
    install_packages libnss-ldap libpam-ldap krb5-user
    backup_file /etc/pam.d/common-auth
    backup_file /etc/pam.d/common-account
    echo "auth sufficient pam_ldap.so" >> /etc/pam.d/common-auth
    echo "account sufficient pam_ldap.so" >> /etc/pam.d/common-account
    backup_file /etc/krb5.conf
    cat <<EOF >> /etc/krb5.conf
[realms]
EXAMPLE.COM = {
    kdc = kerberos.example.com
    admin_server = kerberos.example.com
}
EOF
    systemctl restart nslcd
    log_message "LDAP/Kerberos configurado." "SUCCESS"
}

# ---------------- FILESYSTEM SEGURO ----------------
secure_filesystem() {
    log_message "Aplicando montagem segura de arquivos..." "INFO"
    backup_file /etc/fstab
    for FS in "/tmp" "/var/tmp" "/dev/shm"; do
        echo "none $FS tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
        mount -o remount,noexec,nosuid,nodev $FS
    done
    log_message "Montagem segura aplicada." "SUCCESS"
}

# ---------------- FAIL2BAN ----------------
configure_fail2ban() {
    log_message "Configurando Fail2Ban..." "INFO"
    install_packages fail2ban
    systemctl enable fail2ban && systemctl restart fail2ban
    log_message "Fail2Ban configurado." "SUCCESS"
}

# ---------------- THREAT INTELLIGENCE ----------------
update_threat_intelligence() {
    log_message "Atualizando lista de IPs maliciosos..." "INFO"
    # Exemplo: AlienVault OTX feed (simplificado)
    check_command curl
    curl -s https://reputation.alienvault.com/reputation.generic | grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | while read ip; do
        iptables -A INPUT -s $ip -j DROP
    done
    log_message "Lista de IPs maliciosos aplicada no firewall." "SUCCESS"
}

# ---------------- CLI INTERATIVO ----------------
main_menu() {
    echo "===== SecureMilitaryHardening 2025 ====="
    echo "1) Configurar Firewall"
    echo "2) Hardening Kernel"
    echo "3) Configurar PAM"
    echo "4) Configurar LDAP/Kerberos"
    echo "5) Aplicar Filesystem Seguro"
    echo "6) Configurar Fail2Ban"
    echo "7) Atualizar Threat Intelligence"
    echo "8) Executar Tudo"
    echo "9) Sair"
    read -rp "Escolha uma opção: " choice
    case $choice in
        1) configure_firewall ;;
        2) harden_kernel ;;
        3) configure_pam ;;
        4) configure_authentication ;;
        5) secure_filesystem ;;
        6) configure_fail2ban ;;
        7) update_threat_intelligence ;;
        8) configure_firewall && harden_kernel && configure_pam && configure_authentication && secure_filesystem && configure_fail2ban && update_threat_intelligence ;;
        9) exit 0 ;;
        *) echo "Opção inválida" ;;
    esac
}

# ---------------- EXECUÇÃO ----------------
install_packages iptables nftables fail2ban curl libpam-modules-utils sudo libnss-ldap libpam-ldap krb5-user
while true; do main_menu; done
