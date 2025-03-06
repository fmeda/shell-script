#!/bin/bash

# Função para solicitar entrada do usuário com validação
prompt() {
    local prompt_message=$1
    local var_name=$2
    while true; do
        read -p "$prompt_message: " $var_name
        # Validar se a entrada não está vazia
        if [[ -z "${!var_name}" ]]; then
            echo "Entrada inválida! Por favor, forneça uma resposta válida."
        else
            break
        fi
    done
}

# Função para validar IP
validate_ip() {
    local ip=$1
    local valid_ip="^([0-9]{1,3}\.){3}[0-9]{1,3}$"
    if [[ ! $ip =~ $valid_ip ]]; then
        echo "Endereço IP inválido: $ip. Por favor, forneça um IP válido."
        exit 1
    fi
}

# Função para validar ASN
validate_asn() {
    local asn=$1
    if ! [[ $asn =~ ^[0-9]+$ ]]; then
        echo "ASN inválido. Por favor, forneça um ASN numérico válido."
        exit 1
    fi
}

# Função para validar máscara de sub-rede
validate_subnet() {
    local subnet=$1
    local valid_subnet="^(255\.){3}255$|^(255\.){2}255\.$"
    if [[ ! $subnet =~ $valid_subnet ]]; then
        echo "Máscara de sub-rede inválida: $subnet. Por favor, forneça uma máscara válida."
        exit 1
    fi
}

# Função para fazer backup da configuração atual
backup_configuration() {
    echo "Fazendo backup da configuração atual..."
    ssh $ssh_user@$mgmt_ip "cli show configuration | save /var/tmp/juniper_backup.conf"
    echo "Backup realizado com sucesso."
}

# Função para adicionar regras de firewall
add_firewall_rule() {
    local rule_name=$1
    local action=$2
    local from_zone=$3
    local to_zone=$4
    local protocol=$5
    local port=$6

    cat <<EOL >> /tmp/juniper_config.txt
# Definindo regra de firewall: $rule_name
set security policies from-zone $from_zone to-zone $to_zone policy $rule_name match source-address any destination-address any application $protocol
set security policies from-zone $from_zone to-zone $to_zone policy $rule_name then $action
set security policies from-zone $from_zone to-zone $to_zone policy $rule_name then permit application-services
set security policies from-zone $from_zone to-zone $to_zone policy $rule_name then application $protocol
EOL
}

# Função para configurar políticas de segurança
configure_security_policy() {
    local from_zone=$1
    local to_zone=$2
    local rule_name=$3
    local action=$4
    local protocol=$5
    local port=$6

    add_firewall_rule "$rule_name" "$action" "$from_zone" "$to_zone" "$protocol" "$port"
}

# Função para proteger arquivo de configuração contra apagamento acidental
protect_config_file() {
    local config_file=$1
    echo "Protegendo o arquivo de configuração contra apagamento acidental..."
    chmod 444 $config_file  # Torna o arquivo somente leitura
    echo "Arquivo de configuração protegido com sucesso!"
}

# Função para reiniciar o dispositivo
reboot_device() {
    local reboot_choice=$1
    if [[ "$reboot_choice" == "s" || "$reboot_choice" == "S" ]]; then
        echo "Reiniciando o dispositivo..."
        ssh $ssh_user@$mgmt_ip "request system reboot"
        echo "Dispositivo reiniciado com sucesso."
    fi
}

# Função para configurar múltiplas zonas de segurança
configure_security_zones() {
    local zones=("$@")
    for zone in "${zones[@]}"; do
        echo "Configurando zona de segurança: $zone"
        cat <<EOL >> /tmp/juniper_config.txt
set security zones security-zone $zone interfaces em0.0
set security zones security-zone $zone host-inbound-traffic system-services all
EOL
    done
}

# Função para configurar protocolos de roteamento
configure_routing_protocol() {
    local protocol=$1
    local asn=$2
    local mgmt_ip=$3

    if [[ "$protocol" == "OSPF" ]]; then
        echo "Configurando OSPF..."
        cat <<EOL >> /tmp/juniper_config.txt
set protocols ospf area 0.0.0.0 interface em0.0
EOL
    elif [[ "$protocol" == "BGP" ]]; then
        echo "Configurando BGP com ASN $asn..."
        cat <<EOL >> /tmp/juniper_config.txt
set protocols bgp group external type external
set protocols bgp group external local-as $asn
set protocols bgp group external neighbor $mgmt_ip
EOL
    fi
}

# Função para coletar informações iniciais
collect_initial_info() {
    prompt "Digite o nome do dispositivo" device_name
    prompt "Digite o endereço IP da interface de gerenciamento" mgmt_ip
    validate_ip $mgmt_ip
    prompt "Digite a máscara de sub-rede da interface de gerenciamento" mgmt_subnet
    validate_subnet $mgmt_subnet
    prompt "Digite o gateway da interface de gerenciamento" mgmt_gateway
    validate_ip $mgmt_gateway
    prompt "Digite o nome do domínio (ex: example.com)" domain_name
    prompt "Digite o endereço do servidor NTP" ntp_server
    validate_ip $ntp_server
    prompt "Digite o endereço de seu servidor de logs Syslog" syslog_server
    validate_ip $syslog_server
    prompt "Digite a senha do usuário root" root_password
    prompt "Digite o nome de usuário para acesso SSH" ssh_user
    prompt "Digite a senha do usuário SSH" ssh_password
    prompt "Digite o endereço IP para acesso remoto (ex: 192.168.1.0/24)" ssh_access_ip
    validate_ip $ssh_access_ip
    prompt "Digite o nome do protocolo de roteamento (ex: OSPF, BGP)" routing_protocol
    prompt "Digite o IP da interface de loopback (ex: 10.0.0.1)" loopback_ip
    validate_ip $loopback_ip
    prompt "Digite o nome da zona de segurança (ex: trust, untrust)" security_zone
}

# Função para adicionar regras de firewall
add_firewall_rules_interactive() {
    local add_firewall
    prompt "Deseja adicionar regras de firewall? (s/n)" add_firewall
    if [[ "$add_firewall" == "s" || "$add_firewall" == "S" ]]; then
        while true; do
            prompt "Digite a zona de origem para a política (ex: trust)" from_zone
            prompt "Digite a zona de destino para a política (ex: untrust)" to_zone
            prompt "Digite o nome da regra (ex: allow-http)" rule_name
            prompt "Digite a ação para a política (permit/deny)" action
            prompt "Digite o protocolo para a política (ex: http, tcp, udp)" protocol
            prompt "Digite a porta para a política (ex: 80 para http)" port
            configure_security_policy "$from_zone" "$to_zone" "$rule_name" "$action" "$protocol" "$port"

            prompt "Deseja adicionar outra regra? (s/n)" add_another
            if [[ "$add_another" != "s" && "$add_another" != "S" ]]; then
                break
            fi
        done
    fi
}

# Início do Script
collect_initial_info
backup_configuration

# Configuração de zonas de segurança
configure_security_zones "$security_zone"

# Configuração de protocolo de roteamento
if [[ "$routing_protocol" == "BGP" ]]; then
    prompt "Digite o ASN para BGP" asn
    validate_asn $asn
fi
configure_routing_protocol "$routing_protocol" "$asn" "$mgmt_ip"

# Adicionar regras de firewall
add_firewall_rules_interactive

# Gerar comandos de configuração Junos
cat <<EOL > /tmp/juniper_config.txt
# Configuração Inicial do Dispositivo Juniper
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
EOL

# Proteger arquivo de configuração
protect_config_file "/tmp/juniper_config.txt"

# Perguntar se o administrador deseja reiniciar o dispositivo
prompt "Deseja reiniciar o dispositivo agora? (s/n)" reboot_choice
reboot_device "$reboot_choice"

echo "Configuração gerada com sucesso em /tmp/juniper_config.txt"
