#!/bin/bash
# =======================================================
# SCRIPT CORPORATIVO DE INSTALAÇÃO E CONFIGURAÇÃO OXIDIZED
# Autor: Fabiano Aparecido
# Data: 21/10/2025
# Versão: CMNI v2.0 - com Alertas Integrados
# =======================================================

set -e
LOG_FILE="/var/log/oxidized_setup.log"
ALERT_LOG="/var/log/oxidized_alerts.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a $LOG_FILE
}

# =======================================================
# 1. INSTALAÇÃO DE DEPENDÊNCIAS
# =======================================================
install_dependencies() {
    log "Atualizando sistema e instalando dependências..."
    sudo apt update -y && sudo apt upgrade -y
    sudo apt install -y git ruby ruby-dev libsqlite3-dev build-essential libssl-dev nmap ipcalc curl msmtp
}

# =======================================================
# 2. INSTALAÇÃO OXIDIZED
# =======================================================
install_oxidized() {
    log "Instalando Oxidized..."
    sudo gem install oxidized oxidized-script oxidized-web
}

# =======================================================
# 3. CONFIGURAÇÃO INICIAL
# =======================================================
configure_oxidized() {
    log "Criando usuário e diretórios..."
    sudo useradd -m -s /bin/bash oxidized || log "Usuário já existente"
    sudo mkdir -p /home/oxidized/.config/oxidized
    sudo chown -R oxidized:oxidized /home/oxidized/.config

    CONFIG_FILE="/home/oxidized/.config/oxidized/config"
    if [ ! -f "$CONFIG_FILE" ]; then
        log "Gerando arquivo de configuração base..."
        sudo tee $CONFIG_FILE > /dev/null <<EOL
---
username: admin
password: admin
model: junos
interval: 3600
use_syslog: true
debug: false
threads: 30
timeout: 20
retries: 3
prompt: !ruby/regexp /^([\w.@()-]+[#>]\s?)$/
rest: 0.0.0.0:8888
next_adds_job: true

groups: {}
models: {}
pid: /home/oxidized/.config/oxidized/oxidized.pid
log: /home/oxidized/.config/oxidized/oxidized.log
output:
  git:
    user: Oxidized
    email: oxidized@example.com
    repo: "/home/oxidized/.config/oxidized/configs.git"

source:
  default: csv
  csv:
    file: "/home/oxidized/.config/oxidized/router.db"
EOL
        sudo chown oxidized:oxidized $CONFIG_FILE
    fi

    log "Inicializando repositório Git..."
    sudo -u oxidized git init /home/oxidized/.config/oxidized/configs.git
}

# =======================================================
# 4. SERVIÇO SYSTEMD
# =======================================================
create_systemd_service() {
    SERVICE_FILE="/etc/systemd/system/oxidized.service"
    sudo tee $SERVICE_FILE > /dev/null <<EOL
[Unit]
Description=Oxidized network configuration backup
After=network.target

[Service]
Type=simple
User=oxidized
ExecStart=/usr/local/bin/oxidized
Restart=always

[Install]
WantedBy=multi-user.target
EOL
    sudo systemctl daemon-reload
    sudo systemctl enable oxidized
    sudo systemctl start oxidized
}

# =======================================================
# 5. VALIDAÇÃO DE MODELO SUPORTADO
# =======================================================
validate_model() {
    SUPPORTED=("cisco" "juniper" "fortinet" "huawei" "mikrotik" "arista" "paloalto")
    MODEL=$1
    for m in "${SUPPORTED[@]}"; do
        [[ "$MODEL" == "$m" ]] && return 0
    done
    return 1
}

# =======================================================
# 6. ADIÇÃO DE DISPOSITIVOS
# =======================================================
add_devices() {
    CONFIG_DB="/home/oxidized/.config/oxidized/router.db"

    echo "Deseja adicionar um dispositivo único ou range de IPs? (single/range)"
    read choice

    if [[ "$choice" == "single" ]]; then
        echo "Digite o IP:"
        read ip_list
    else
        echo "Digite o range (ex: 192.168.1.0/24 ou 192.168.1.1-192.168.1.254):"
        read ip_list
    fi

    echo "Modelo/vendor (cisco, juniper, fortinet...):"
    read model
    if ! validate_model $model; then
        log "Modelo não suportado: $model"
        exit 1
    fi

    echo "Grupo lógico (core, edge, access):"
    read group
    echo "Usuário SSH/Telnet:"
    read user
    echo "Senha SSH/Telnet:"
    read -s pass

    if [[ "$choice" == "range" ]]; then
        log "Descobrindo IPs ativos..."
        ip_list=$(nmap -n -sP $ip_list | grep "Nmap scan report for" | awk '{print $5}')
    fi

    for ip in $ip_list; do
        ping -c 1 -W 1 $ip &>/dev/null
        if [ $? -ne 0 ]; then
            log "Dispositivo $ip offline."
            echo "$(date) - $ip OFFLINE" >> $ALERT_LOG
            continue
        fi

        if ! grep -q "$ip" $CONFIG_DB; then
            echo "$ip,$model,$group" >> $CONFIG_DB
            log "Dispositivo $ip adicionado."
        fi
    done

    sudo systemctl restart oxidized
    log "Coleta inicial disparada."
}

# =======================================================
# 7. CONFIGURAÇÃO DE ALERTAS
# =======================================================
configure_alerts() {
    ALERT_DIR="/home/oxidized/.config/oxidized/configs.git/hooks/post-commit"
    mkdir -p $(dirname $ALERT_DIR)
    sudo -u oxidized tee $ALERT_DIR > /dev/null <<'EOL'
#!/bin/bash
REPO_PATH="/home/oxidized/.config/oxidized/configs.git"
LAST_COMMIT=$(git --git-dir=$REPO_PATH rev-parse --short HEAD)
CHANGE=$(git --git-dir=$REPO_PATH show --name-only $LAST_COMMIT | tail -n +7)

SLACK_WEBHOOK="https://hooks.slack.com/services/SEU_WEBHOOK"
EMAIL_TO="network-team@example.com"

MSG="Alteração detectada pelo Oxidized:
Commit: $LAST_COMMIT
Arquivos alterados:
$CHANGE"

# Envio Slack
curl -X POST -H 'Content-type: application/json' \
--data "{\"text\":\"$MSG\"}" $SLACK_WEBHOOK

# Envio Email
echo "$MSG" | mail -s "[Oxidized] Alteração detectada" $EMAIL_TO

echo "$(date) - Alerta disparado - $LAST_COMMIT" >> /var/log/oxidized_alerts.log
EOL
    sudo chmod +x $ALERT_DIR
    log "Webhook e alerta de email configurados."
}

# =======================================================
# 8. EXECUÇÃO PRINCIPAL
# =======================================================
main() {
    log "==== Iniciando instalação completa do Oxidized CMNI v2 ===="
    install_dependencies
    install_oxidized
    configure_oxidized
    create_systemd_service
    add_devices
    configure_alerts
    log "==== Instalação concluída com sucesso! ===="
    echo "Acesse: http://<IP_DO_SERVIDOR>:8888"
}

main
