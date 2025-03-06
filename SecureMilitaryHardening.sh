#!/bin/bash

# Nome do Script: SecureMilitaryHardening.sh
# Descrição: Script avançado de hardening para ambientes Linux militares e de alta segurança.
# Autor: [Seu Nome]
# Versão: 2.0
# Data: [Data Atual]
# Licença: MIT
# ---------------------------------------------------------

LOG_FILE="/var/log/military_hardening.log"

log_message() {
    local MESSAGE="$1"
    local LEVEL="$2"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$LEVEL] - $MESSAGE" | tee -a $LOG_FILE
}

# ---------------------------------------------------------
# 1. CONFIGURANDO FIREWALL AVANÇADO (iptables + nftables)
# ---------------------------------------------------------
configure_firewall() {
    log_message "Configurando firewall iptables e nftables..." "INFO"

    # Flush regras existentes
    iptables -F
    iptables -X
    iptables -Z

    # Definir políticas padrão
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    # Permitir tráfego no loopback
    iptables -A INPUT -i lo -j ACCEPT

    # Permitir tráfego estabelecido
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Permitir SSH apenas de redes seguras (modifique conforme necessário)
    iptables -A INPUT -p tcp --dport 22 -s 192.168.1.0/24 -j ACCEPT

    # Bloquear portas suspeitas usadas por ataques comuns
    iptables -A INPUT -p tcp --match multiport --dports 23,2323,3389 -j DROP

    iptables-save > /etc/iptables/rules.v4

    # Configuração do nftables
    cat <<EOF > /etc/nftables.conf
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        iif "lo" accept
        tcp dport ssh accept
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}
EOF

    systemctl enable nftables
    systemctl start nftables

    log_message "Firewall configurado com sucesso!" "SUCCESS"
}

# ---------------------------------------------------------
# 2. HARDENING DO KERNEL (Sysctl + Modprobe)
# ---------------------------------------------------------
harden_kernel() {
    log_message "Aplicando hardening do kernel..." "INFO"

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

    # Desabilitar módulos de kernel não utilizados
    echo "install cramfs /bin/true" >> /etc/modprobe.d/disable-filesystems.conf
    echo "install freevxfs /bin/true" >> /etc/modprobe.d/disable-filesystems.conf
    echo "install jffs2 /bin/true" >> /etc/modprobe.d/disable-filesystems.conf
    echo "install hfs /bin/true" >> /etc/modprobe.d/disable-filesystems.conf
    echo "install hfsplus /bin/true" >> /etc/modprobe.d/disable-filesystems.conf
    echo "install squashfs /bin/true" >> /etc/modprobe.d/disable-filesystems.conf
    echo "install udf /bin/true" >> /etc/modprobe.d/disable-filesystems.conf
    echo "install vfat /bin/true" >> /etc/modprobe.d/disable-filesystems.conf

    log_message "Configurações do kernel aplicadas com sucesso!" "SUCCESS"
}

# ---------------------------------------------------------
# 3. CONFIGURANDO PAM PARA AUTENTICAÇÃO SEGURA
# ---------------------------------------------------------
configure_pam() {
    log_message "Configurando PAM para segurança máxima..." "INFO"

    sed -i 's/^password\s*requisite\s*pam_pwquality.so.*/password requisite pam_pwquality.so retry=3 minlen=14 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password
    sed -i 's/^auth\s*required\s*pam_tally2.so.*/auth required pam_tally2.so deny=5 unlock_time=600/' /etc/pam.d/common-auth

    log_message "PAM configurado com sucesso!" "SUCCESS"
}

# ---------------------------------------------------------
# 4. CONFIGURANDO AUTENTICAÇÃO VIA LDAP/KERBEROS
# ---------------------------------------------------------
configure_authentication() {
    log_message "Configurando autenticação LDAP/Kerberos..." "INFO"

    apt-get install -y libnss-ldap libpam-ldap krb5-user

    echo "auth sufficient pam_ldap.so" >> /etc/pam.d/common-auth
    echo "account sufficient pam_ldap.so" >> /etc/pam.d/common-account

    echo "[realms]
    EXAMPLE.COM = {
        kdc = kerberos.example.com
        admin_server = kerberos.example.com
    }" >> /etc/krb5.conf

    systemctl restart nslcd
    log_message "Autenticação LDAP/Kerberos configurada com sucesso!" "SUCCESS"
}

# ---------------------------------------------------------
# 5. CONFIGURANDO MONTAGEM SEGURA DE SISTEMAS DE ARQUIVOS
# ---------------------------------------------------------
secure_filesystem() {
    log_message "Aplicando segurança no sistema de arquivos..." "INFO"

    echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
    echo "none /var/tmp tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
    echo "none /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab

    mount -o remount,noexec,nosuid,nodev /tmp
    mount -o remount,noexec,nosuid,nodev /var/tmp
    mount -o remount,noexec,nosuid,nodev /dev/shm

    log_message "Montagem segura aplicada!" "SUCCESS"
}

# ---------------------------------------------------------
# 6. ATIVANDO FAIL2BAN
::contentReference[oaicite:0]{index=0}
 
