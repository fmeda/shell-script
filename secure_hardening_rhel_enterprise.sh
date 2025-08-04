#!/bin/bash

# ================================
# HARDENING POS OPERAÇÃO - AVANÇADO
# Criptografia + Backup + Relatório + Git + Hash + Notificação
# Autor: Fabiano A. (Otimizador IA)
# ================================

set -euo pipefail

# ========= VARIÁVEIS =========
ARQUIVOS_CRIPTOGRAFAR=("/etc/pki/tls/private/server.key")
BACKUP_DIR="/var/backups/secure"
REMOTE_RCLONE_REMOTE="securebackup:server"
GIT_REPO_DIR="/opt/security_audit_log"
LOG_FILE="/var/log/secure_hardening.log"
HTML_REPORT="/var/log/secure_hardening.html"
PDF_REPORT="/var/log/secure_hardening.pdf"
GPG_KEY="admin@seudominio.com"
EMAIL_ADMIN="admin@seudominio.com"
HOST_ID=$(hostname)
TIMESTAMP=$(date +'%F_%H-%M-%S')
HASH_FILE="$BACKUP_DIR/sha256sums.txt"

# ========= VALIDA DEPENDÊNCIAS =========
checar_dependencias() {
    echo "[INFO] Verificando dependências..." | tee -a "$LOG_FILE"
    for cmd in gpg rclone git wkhtmltopdf sha256sum; do
        if ! command -v "$cmd" &>/dev/null; then
            echo "[ERRO] Dependência ausente: $cmd" | tee -a "$LOG_FILE"
            exit 1
        fi
    done
    echo "[OK] Todas as dependências estão instaladas." | tee -a "$LOG_FILE"
}

# ========= ENCRIPTA ARQUIVOS =========
criptografar_arquivos() {
    mkdir -p "$BACKUP_DIR"
    for arquivo in "${ARQUIVOS_CRIPTOGRAFAR[@]}"; do
        if [[ -f "$arquivo" ]]; then
            nome_arquivo=$(basename "$arquivo")
            gpg --yes --batch --encrypt --recipient "$GPG_KEY" "$arquivo" -o "$BACKUP_DIR/${nome_arquivo}.gpg"
            echo "[OK] Arquivo criptografado: $nome_arquivo.gpg" | tee -a "$LOG_FILE"
        else
            echo "[AVISO] Arquivo não encontrado: $arquivo" | tee -a "$LOG_FILE"
        fi
    done
}

# ========= GERA HASH DE INTEGRIDADE =========
gerar_hashes() {
    echo "[INFO] Gerando hashes SHA-256..." | tee -a "$LOG_FILE"
    sha256sum "$BACKUP_DIR"/*.gpg > "$HASH_FILE"
    echo "[OK] Arquivo de integridade gerado: $HASH_FILE" | tee -a "$LOG_FILE"
}

# ========= BACKUP REMOTO =========
backup_remoto() {
    echo "[INFO] Enviando backup para storage remoto..." | tee -a "$LOG_FILE"
    rclone mkdir "$REMOTE_RCLONE_REMOTE"
    rclone copy "$BACKUP_DIR" "$REMOTE_RCLONE_REMOTE" --progress
    echo "[OK] Backup remoto enviado com sucesso." | tee -a "$LOG_FILE"
}

# ========= EXPORTA RELATÓRIO =========
exportar_relatorio() {
    echo "[INFO] Gerando relatório HTML/PDF..." | tee -a "$LOG_FILE"
    {
        echo "<html><head><title>Relatório de Hardening - $HOST_ID</title></head><body><pre>"
        cat "$LOG_FILE"
        echo "</pre></body></html>"
    } > "$HTML_REPORT"

    if command -v wkhtmltopdf &>/dev/null; then
        wkhtmltopdf "$HTML_REPORT" "$PDF_REPORT"
        echo "[OK] Relatório PDF gerado: $PDF_REPORT" | tee -a "$LOG_FILE"
    else
        echo "[WARN] wkhtmltopdf não está instalado." | tee -a "$LOG_FILE"
    fi
}

# ========= LOG EM GIT =========
log_em_git() {
    echo "[INFO] Commitando log no Git local com GPG..." | tee -a "$LOG_FILE"
    mkdir -p "$GIT_REPO_DIR"
    cp "$LOG_FILE" "$GIT_REPO_DIR/hardening_${TIMESTAMP}.log"
    cp "$HASH_FILE" "$GIT_REPO_DIR/sha256_${TIMESTAMP}.txt"
    pushd "$GIT_REPO_DIR" >/dev/null
    git init -q
    git config user.name "SecureBot"
    git config user.email "$GPG_KEY"
    git add .
    git commit -S -m "Hardening Log $TIMESTAMP" || echo "[WARN] Commit falhou." | tee -a "$LOG_FILE"
    popd >/dev/null
    echo "[OK] Log versionado com Git e GPG." | tee -a "$LOG_FILE"
}

# ========= NOTIFICAÇÃO POR E-MAIL =========
enviar_email() {
    if command -v mail &>/dev/null && [[ -n "$EMAIL_ADMIN" ]]; then
        SUBJECT="Relatório de Hardening - $HOST_ID - $TIMESTAMP"
        mail -s "$SUBJECT" "$EMAIL_ADMIN" < "$LOG_FILE"
        echo "[OK] Relatório enviado por e-mail para $EMAIL_ADMIN" | tee -a "$LOG_FILE"
    else
        echo "[INFO] Cliente de e-mail (mailx) não configurado. Notificação não enviada." | tee -a "$LOG_FILE"
    fi
}

# ========= EXECUÇÃO PRINCIPAL =========

main() {
    echo "==============================" | tee -a "$LOG_FILE"
    echo " INÍCIO DO HARDENING POS OPERAÇÃO - $TIMESTAMP " | tee -a "$LOG_FILE"
    echo " Host: $HOST_ID " | tee -a "$LOG_FILE"
    echo "==============================" | tee -a "$LOG_FILE"

    checar_dependencias
    criptografar_arquivos
    gerar_hashes
    backup_remoto
    exportar_relatorio
    log_em_git
    enviar_email

    echo "[FIM] Processo concluído com sucesso." | tee -a "$LOG_FILE"
}

main "$@"
