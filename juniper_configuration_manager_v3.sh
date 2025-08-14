#!/bin/bash
# Script de configuração Juniper Ultra-Segura
# Autor: Fabiano Aparecido
# Funcionalidades:
# - Hardening SSH/NTMP/SNMP/ICMP
# - Políticas de firewall via CSV
# - Senhas protegidas com AES temporário
# - Logs detalhados e backups

CONFIG_FILE="/tmp/juniper_config_secure.txt"
LOG_FILE="/tmp/juniper_secure.log"
TMP_PASS_FILE="/tmp/juniper_pass.enc"

# -------- Funções de utilidade --------
log_info() { echo -e "[INFO] $1" | tee -a "$LOG_FILE"; }
log_warn() { echo -e "\e[33m[WARN] $1\e[0m" | tee -a "$LOG_FILE"; }
log_error() { echo -e "\e[31m[ERROR] $1\e[0m" | tee -a "$LOG_FILE"; }

prompt() {
    local msg=$1 var=$2 silent=${3:-0}
    while true; do
        if [[ $silent -eq 1 ]]; then read -s -p "$msg: " $var; echo; else read -p "$msg: " $var; fi
        [[ -n "${!var}" ]] && break || log_warn "Entrada inválida!"
    done
}

validate_ip() { [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { log_error "IP inválido: $1"; exit 1; } }
validate_cidr() { [[ $1 =~ ^([0-9]{1,2})$ ]] && (( $1>=0 && $1<=32 )) || { log_error "CIDR inválido: $1"; exit 1; } }
validate_asn() { [[ $1 =~ ^[0-9]+$ ]] || { log_error "ASN inválido: $1"; exit 1; } }

protect_file() { chmod 444 "$1"; log_info "Arquivo protegido: $1"; }

encrypt_passwords() {
    echo -n "$root_password:$ssh_password" | openssl enc -aes-256-cbc -a -salt -pass pass:"$pass_key" > "$TMP_PASS_FILE"
    log_info "Senhas criptografadas em $TMP_PASS_FILE"
}

decrypt_passwords() {
    local decrypted
    decrypted=$(openssl enc -aes-256-cbc -d -a -in "$TMP_PASS_FILE" -pass pass:"$pass_key")
    IFS=":" read -r root_password ssh_password <<< "$decrypted"
}

# -------- Backup --------
backup_configuration() {
    log_info "Criando backup remoto..."
    ssh "$ssh_user@$mgmt_ip" "cli show configuration | save /var/tmp/juniper_backup_$(date +%F).conf"
    log_info "Backup concluído."
}

# -------- Zonas e Firewall --------
configure_security_zones() {
    for zone in "$@"; do
        echo "set security zones security-zone $zone interfaces em0.0" >> "$CONFIG_FILE"
        echo "set security zones security-zone $zone host-inbound-traffic system-services all" >> "$CONFIG_FILE"
        log_info "Zona configurada: $zone"
    done
}

add_firewall_rule() {
    local name=$1 action=$2 from_zone=$3 to_zone=$4 protocol=$5 port=$6
    cat <<EOL >> "$CONFIG_FILE"
set security policies from-zone $from_zone to-zone $to_zone policy $name match source-address any destination-address any application $protocol
set security policies from-zone $from_zone to-zone $to_zone policy $name then $action
set security policies from-zone $from_zone to-zone $to_zone policy $name then permit application-services
EOL
    log_info "Regra adicionada: $name"
}

add_firewall_rules_from_csv() {
    local csv_file=$1
    [[ ! -f "$csv_file" ]] && { log_warn "CSV não encontrado: $csv_file"; return; }
    while IFS=, read -r from_zone to_zone rule_name action protocol port; do
        add_firewall_rule "$rule_name" "$action" "$from_zone" "$to_zone" "$protocol" "$port"
    done < "$csv_file"
    log_info "Regras carregadas do CSV: $csv_file"
}

# -------- Roteamento --------
configure_routing_protocol() {
    local proto=$1 asn=$2 mgmt_ip=$3
    if [[ "$proto" == "OSPF" ]]; then echo "set protocols ospf area 0.0.0.0 interface em0.0" >> "$CONFIG_FILE"
    elif [[ "$proto" == "BGP" ]]; then
        echo "set protocols bgp group external type external" >> "$CONFIG_FILE"
        echo "set protocols bgp group external local-as $asn" >> "$CONFIG_FILE"
        echo "set protocols bgp group external neighbor $mgmt_ip" >> "$CONFIG_FILE"
    fi
    log_info "Protocolo $proto configurado"
}

# -------- Coleta segura --------
collect_initial_info() {
    prompt "Nome do dispositivo" device_name
    prompt "IP da interface de gerenciamento" mgmt_ip; validate_ip "$mgmt_ip"
    prompt "CIDR da interface de gerenciamento (0-32)" mgmt_subnet; validate_cidr "$mgmt_subnet"
    prompt "Gateway de gerenciamento" mgmt_gateway; validate_ip "$mgmt_gateway"
    prompt "Nome do domínio" domain_name
    prompt "Servidor NTP" ntp_server; validate_ip "$ntp_server"
    prompt "Servidor Syslog" syslog_server; validate_ip "$syslog_server"
    prompt "Senha root" root_password 1
    prompt "Usuário SSH" ssh_user
    prompt "Senha SSH" ssh_password 1
    prompt "Chave temporária para criptografia de senhas" pass_key 1
    prompt "IP para acesso SSH remoto" ssh_access_ip; validate_ip "$ssh_access_ip"
    prompt "Protocolo de roteamento (OSPF/BGP)" routing_protocol
    prompt "IP da loopback" loopback_ip; validate_ip "$loopback_ip"
    prompt "Nome da zona de segurança (trust/untrust)" security_zone
    prompt "CSV com regras de firewall (opcional)" csv_file
}

# -------- Reinício --------
reboot_device() { [[ "$1" =~ ^[sS]$ ]] && { ssh "$ssh_user@$mgmt_ip" "request system reboot"; log_info "Dispositivo reiniciado"; } }

# -------- Execução --------
collect_initial_info
encrypt_passwords
backup_configuration

cat <<EOL > "$CONFIG_FILE"
set system host-name $device_name
set interfaces em0 unit 0 family inet address $mgmt_ip/$mgmt_subnet
set routing-options static route 0.0.0.0/0 next-hop $mgmt_gateway
set system name-server $ntp_server
set system domain-name $domain_name
set system root-authentication plain-text-password $root_password
set system login user $ssh_user class super-user authentication plain-text-password $ssh_password
set system time-zone UTC
set system ntp server $ntp_server
set system syslog host $syslog_server any info
set system services ssh root-login deny
set system services ssh protocol-version v2
set system services ssh listen-address $ssh_access_ip
set interfaces lo0 unit 0 family inet address $loopback_ip/32
set system services snmp community public authorization read-only
set system services dhcp-local-server group default interface em0.0
set system services telnet disable
set system icmp rate-limit all
EOL

configure_security_zones "$security_zone"
[[ "$routing_protocol" == "BGP" ]] && { prompt "ASN para BGP" asn; validate_asn "$asn"; }
configure_routing_protocol "$routing_protocol" "$asn" "$mgmt_ip"

# Adicionar regras via CSV
[[ -n "$csv_file" ]] && add_firewall_rules_from_csv "$csv_file"

protect_file "$CONFIG_FILE"
rm -f "$TMP_PASS_FILE"
log_info "Senhas temporárias removidas"

prompt "Deseja reiniciar o dispositivo agora? (s/n)" reboot_choice
reboot_device "$reboot_choice"

log_info "Configuração segura gerada: $CONFIG_FILE"
