#!/usr/bin/env bash
# ===================================================================
# SECURE-DOCKER-PRO-ADVANCED V2
# Ferramenta Avançada para Segurança e Gerenciamento de Containers Docker
# Melhorias: modularização, sanitização, config externa, logging avançado
# ===================================================================

set -euo pipefail
trap rollback_on_error ERR

# -------------------------------
# CONFIGURAÇÃO EXTERNA
# -------------------------------
CONFIG_FILE="./secure-docker-pro.conf"

# Carrega arquivo de configuração se existir
if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
fi

# Variáveis padrão (podem ser sobrescritas pelo config)
IMAGE="${IMAGE:-nginx:latest}"
CONTAINER_NAME="${CONTAINER_NAME:-secure_container}"
SLACK_WEBHOOK="${SLACK_WEBHOOK:-}"
EMAIL_NOTIF="${EMAIL_NOTIF:-}"
REPORT_DIR="${REPORT_DIR:-./relatorios}"
DATE=$(date '+%Y-%m-%d_%H-%M-%S')
DRY_RUN=${DRY_RUN:-false}
AUTO_MODE=${AUTO_MODE:-false}
LOG_LEVEL="${LOG_LEVEL:-INFO}"  # DEBUG, INFO, WARN, ERROR

REQUIRED_CMDS=(docker trivy cosign docker-bench-security curl sendmail)

mkdir -p "$REPORT_DIR"

# -------------------------------
# CORES PARA SAÍDA
# -------------------------------
GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
BLUE="\e[34m"
RESET="\e[0m"

# -------------------------------
# FUNÇÕES DE LOG COM NÍVEL
# -------------------------------
log() {
    local level=$1
    local msg=$2
    declare -A levels=( [DEBUG]=0 [INFO]=1 [WARN]=2 [ERROR]=3 )
    if (( ${levels[$level]} >= ${levels[$LOG_LEVEL]} )); then
        local timestamp
        timestamp=$(date --iso-8601=seconds)
        echo -e "{\"timestamp\":\"$timestamp\",\"level\":\"$level\",\"message\":\"$msg\"}"
        case "$level" in
            ERROR) echo -e "${RED}[ERRO]${RESET} $msg" ;;
            WARN) echo -e "${YELLOW}[AVISO]${RESET} $msg" ;;
            INFO) echo -e "${GREEN}[INFO]${RESET} $msg" ;;
            DEBUG) echo -e "${BLUE}[DEBUG]${RESET} $msg" ;;
        esac
    fi
}

# -------------------------------
# SANITIZAÇÃO E VALIDAÇÃO
# -------------------------------
sanitize_input() {
    # Remove caracteres suspeitos e espaços extras
    local clean
    clean=$(echo "$1" | sed 's/[^a-zA-Z0-9_\-:.\/]//g' | xargs)
    echo "$clean"
}

validate_env() {
    for var in IMAGE CONTAINER_NAME; do
        if [[ -z "${!var}" ]]; then
            log ERROR "Variável $var está vazia. Configure corretamente."
            exit 1
        fi
    done
}

# -------------------------------
# TRATAMENTO DE ERROS E ROLLBACK
# -------------------------------
rollback_on_error() {
    log ERROR "Erro detectado. Iniciando rollback..."
    echo -e "${RED}[ERRO]${RESET} Erro ocorrido. Parando container '$CONTAINER_NAME' se existir."
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    exit 1
}

# -------------------------------
# CHECAGEM DE DEPENDÊNCIAS
# -------------------------------
check_dependencies() {
    log INFO "Verificando dependências..."
    local missing=()
    for cmd in "${REQUIRED_CMDS[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if (( ${#missing[@]} > 0 )); then
        log ERROR "Dependências faltando: ${missing[*]}"
        exit 1
    else
        log INFO "Todas as dependências estão instaladas."
    fi
}

# -------------------------------
# FUNÇÕES DE GERENCIAMENTO E SEGURANÇA
# -------------------------------
verify_image_signature() {
    log INFO "Verificando assinatura da imagem Docker com Cosign..."
    $DRY_RUN || cosign verify "$IMAGE" || {
        log ERROR "Imagem '$IMAGE' não assinada. Execute: cosign sign $IMAGE"
        exit 1
    }
}

scan_trivy() {
    log INFO "Executando scan de vulnerabilidades com Trivy..."
    $DRY_RUN || trivy image --severity CRITICAL,HIGH --exit-code 1 "$IMAGE" || {
        log ERROR "Vulnerabilidades críticas encontradas."
        exit 1
    }
}

scan_docker_bench() {
    log INFO "Executando Docker Bench Security..."
    $DRY_RUN || docker-bench-security.sh --no-colors | tee "$REPORT_DIR/docker-bench-$DATE.txt"
}

scan_tools() {
    scan_trivy
    scan_docker_bench
}

start_container() {
    log INFO "Iniciando container '$CONTAINER_NAME' com imagem '$IMAGE'..."
    $DRY_RUN || docker run -d --name "$CONTAINER_NAME" "$IMAGE"
}

stop_container() {
    log INFO "Parando e removendo container '$CONTAINER_NAME'..."
    $DRY_RUN || docker rm -f "$CONTAINER_NAME" || true
}

restart_container() {
    stop_container
    start_container
}

status_container() {
    log INFO "Status do container '$CONTAINER_NAME':"
    docker ps -a --filter "name=$CONTAINER_NAME"
}

logs_container() {
    echo -e "${BLUE}=== Logs do container $CONTAINER_NAME ===${RESET}"
    docker logs "$CONTAINER_NAME"
}

cleanup_docker() {
    log INFO "Removendo containers parados e imagens dangling..."
    $DRY_RUN || {
        docker container prune -f
        docker image prune -f
    }
}

generate_report() {
    log INFO "Gerando relatório HTML e PDF..."
    local file_html="$REPORT_DIR/report_$DATE.html"
    local file_pdf="$REPORT_DIR/report_$DATE.pdf"
    {
        echo "<html><body><h1>Relatório de Segurança Docker - $DATE</h1><ul>"
        echo "<li>Container: $CONTAINER_NAME</li>"
        echo "<li>Imagem: $IMAGE</li>"
        echo "<li>Status:</li><pre>$(docker ps -a --filter "name=$CONTAINER_NAME")</pre>"
        echo "<li>Trivy Scan:</li><pre>$(trivy image --severity CRITICAL,HIGH --exit-code 0 "$IMAGE" 2>/dev/null)</pre>"
        echo "<li>Docker Bench:</li><pre>$(cat "$REPORT_DIR/docker-bench-$DATE.txt" 2>/dev/null || echo "Não executado")</pre>"
        echo "</ul></body></html>"
    } > "$file_html"

    if command -v wkhtmltopdf &>/dev/null; then
        wkhtmltopdf "$file_html" "$file_pdf" && log INFO "PDF gerado: $file_pdf"
    else
        log WARN "wkhtmltopdf não encontrado, pulando geração de PDF."
    fi

    log INFO "Relatório HTML gerado: $file_html"
}

send_notifications() {
    local msg="Relatório de segurança para container $CONTAINER_NAME usando imagem $IMAGE em $DATE"

    if [[ -n "$SLACK_WEBHOOK" ]]; then
        curl --silent --fail --tlsv1.2 --cacert /etc/ssl/certs/ca-bundle.crt \
            -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"$msg\"}" "$SLACK_WEBHOOK" || log WARN "Falha no envio do alerta Slack"
    fi

    if [[ -n "$EMAIL_NOTIF" ]]; then
        echo -e "Subject: Alerta de Segurança Docker\n\n$msg" | sendmail "$EMAIL_NOTIF" || log WARN "Falha no envio do e-mail"
    fi
}

interactive_menu() {
    echo -e "${BLUE}=== MENU INTERATIVO SECURE-DOCKER-PRO-ADVANCED V2 ===${RESET}"
    PS3="Escolha uma opção: "
    options=("Start" "Stop" "Restart" "Status" "Logs" "Scan" "Cleanup" "Report" "Notify" "Sair")
    select opt in "${options[@]}"; do
        case $opt in
            Start) start_container; break ;;
            Stop) stop_container; break ;;
            Restart) restart_container; break ;;
            Status) status_container; break ;;
            Logs) logs_container; break ;;
            Scan) scan_tools; break ;;
            Cleanup) cleanup_docker; break ;;
            Report) generate_report; break ;;
            Notify) send_notifications; break ;;
            Sair) echo "Saindo..."; exit 0 ;;
            *) echo "Opção inválida." ;;
        esac
    done
}

usage() {
    cat << EOF
Uso: $0 <comando> [opções]

Comandos:
  start          Iniciar container seguro (usa --image e --container)
  stop           Parar e remover container
  restart        Reiniciar container
  status         Mostrar status do container
  logs           Exibir logs do container
  cleanup        Remover containers parados e imagens dangling
  scan           Executar scan Trivy + Docker Bench
  report         Gerar relatório HTML + PDF
  notify         Enviar notificações configuradas (Slack/e-mail)
  interactive    Menu interativo para executar comandos
  help           Exibir este menu de ajuda

Opções comuns:
  --image <imagem>          Define imagem Docker (padrão: $IMAGE)
  --container <nome>        Nome do container (padrão: $CONTAINER_NAME)
  --dry-run                 Simula as ações, sem executar mudanças
  --auto                    Executa todas etapas de segurança e deploy automaticamente

Variáveis de ambiente:
  SLACK_WEBHOOK             Webhook Slack para notificações (opcional)
  EMAIL_NOTIF               E-mail para notificações (opcional, requer sendmail configurado)
  LOG_LEVEL                 Nível de log (DEBUG, INFO, WARN, ERROR). Padrão: INFO

Exemplos:
  $0 start --image nginx:1.25 --container meu_container
  $0 scan --image meu-registry/app:latest
  $0 interactive

EOF
    exit 0
}

main() {
    if [[ $# -eq 0 ]]; then
        usage
    fi

    local cmd=$1
    shift || true

    # Processa opções
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --image) shift; IMAGE=$(sanitize_input "$1") ;;
            --container) shift; CONTAINER_NAME=$(sanitize_input "$1") ;;
            --dry-run) DRY_RUN=true ;;
            --auto) AUTO_MODE=true ;;
            --help) usage ;;
            *) echo "Parâmetro desconhecido: $1"; usage ;;
        esac
        shift
    done

    validate_env
    check_dependencies

    if $AUTO_MODE; then
        verify_image_signature
        scan_tools
        restart_container
        generate_report
        send_notifications
        log INFO "Execução automática concluída com sucesso."
        exit 0
    fi

    case "$cmd" in
        start) start_container ;;
        stop) stop_container ;;
        restart) restart_container ;;
        status) status_container ;;
        logs) logs_container ;;
        cleanup) cleanup_docker ;;
        scan) scan_tools ;;
        report) generate_report ;;
        notify) send_notifications ;;
        interactive) interactive_menu ;;
        help) usage ;;
        *)
            log ERROR "Comando inválido: $cmd"
            usage
            ;;
    esac
}

# -------------------------------
# EXECUÇÃO
# -------------------------------
main "$@"
