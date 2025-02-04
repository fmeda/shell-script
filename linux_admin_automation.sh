#!/bin/bash

# Nome: linux_admin_automation.sh
# Descrição: Automatiza tarefas de um Administrador Linux
# Autor: [Seu Nome]
# Versão: 1.0
# Data: $(date +%Y-%m-%d)

LOG_DIR="/var/log/admin_script"
LOG_FILE="$LOG_DIR/admin_$(date +%Y-%m-%d).log"
BACKUP_DIR="/backup"
AUDIT_LOG="$LOG_DIR/audit.log"

# Criar diretório de logs se não existir
mkdir -p "$LOG_DIR"

# Verificação e instalação de pacotes necessários
check_dependencies() {
    echo "[INFO] Verificando dependências..." | tee -a "$LOG_FILE"
    DEPENDENCIES=(rsync tar ufw fail2ban sysstat auditd)
    for pkg in "${DEPENDENCIES[@]}"; do
        if ! dpkg -l | grep -q "$pkg"; then
            echo "[INFO] Instalando $pkg..." | tee -a "$LOG_FILE"
            apt-get install -y "$pkg" >> "$LOG_FILE" 2>&1
        fi
    done
}

# Monitoramento Diário
monitor_system() {
    echo "[INFO] Iniciando monitoramento diário..." | tee -a "$LOG_FILE"
    echo "--- USO DE RECURSOS ---" | tee -a "$LOG_FILE"
    free -h | tee -a "$LOG_FILE"
    df -h | tee -a "$LOG_FILE"
    echo "--- PROCESSOS ATIVOS ---" | tee -a "$LOG_FILE"
    ps aux --sort=-%mem | head -10 | tee -a "$LOG_FILE"
    echo "--- LOG DE FALHAS DE LOGIN ---" | tee -a "$LOG_FILE"
    grep "Failed password" /var/log/auth.log | tail -10 | tee -a "$LOG_FILE"
}

# Backup Semanal
backup_system() {
    echo "[INFO] Iniciando backup semanal..." | tee -a "$LOG_FILE"
    mkdir -p "$BACKUP_DIR"
    tar -czf "$BACKUP_DIR/backup_$(date +%Y-%m-%d).tar.gz" /etc /home /var/log >> "$LOG_FILE" 2>&1
}

# Auditoria de Segurança
security_audit() {
    echo "[INFO] Executando auditoria de segurança..." | tee -a "$AUDIT_LOG"
    lynis audit system >> "$AUDIT_LOG" 2>&1
    echo "[INFO] Auditoria concluída." | tee -a "$AUDIT_LOG"
}

# Limpeza e Otimização
cleanup_system() {
    echo "[INFO] Iniciando limpeza do sistema..." | tee -a "$LOG_FILE"
    apt autoremove -y >> "$LOG_FILE" 2>&1
    journalctl --vacuum-time=7d >> "$LOG_FILE" 2>&1
}

# Configuração do CRON
setup_cron() {
    echo "[INFO] Configurando tarefas no CRON..." | tee -a "$LOG_FILE"
    CRON_FILE="/etc/cron.d/linux_admin_automation"
    echo "0 2 * * * root /usr/local/bin/linux_admin_automation.sh monitor" > "$CRON_FILE"
    echo "0 3 * * 1 root /usr/local/bin/linux_admin_automation.sh backup" >> "$CRON_FILE"
    echo "0 4 1 * * root /usr/local/bin/linux_admin_automation.sh audit" >> "$CRON_FILE"
    chmod 644 "$CRON_FILE"
    systemctl restart cron
}

# Execução com base nos argumentos passados
case "$1" in
    monitor)
        monitor_system
        ;;
    backup)
        backup_system
        ;;
    audit)
        security_audit
        ;;
    cleanup)
        cleanup_system
        ;;
    setup)
        check_dependencies
        setup_cron
        ;;
    *)
        echo "Uso: $0 {monitor|backup|audit|cleanup|setup}"
        exit 1
esac
