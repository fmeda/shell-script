#!/usr/bin/env bash
# ===================================================================
# SECURE-K8S-PRO FINAL
# Deploy Kubernetes seguro com rollback, pré-check rigoroso,
# validação de hash e ajuda integrada.
# ===================================================================

set -euo pipefail
trap rollback_on_error ERR

# -------------------------------
# VARIÁVEIS PADRÃO
# -------------------------------
APP_NAME="minha-aplicacao"
NAMESPACE="secure-namespace"
IMAGE="nginx:1.23"
DEPLOY_FILE="deployment.yaml"
POLICY_DIR="./policies"
REPORT_DIR="./relatorios"
SLACK_WEBHOOK="${SLACK_WEBHOOK:-}"
DATE=$(date '+%Y-%m-%d_%H-%M-%S')
DRY_RUN=false
AUTO_MODE=false
REQUIRED_CMDS=(kubectl helm trivy checkov cosign)

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
# FUNÇÃO DE HELP PARA ORIENTAR USUÁRIO
# -------------------------------
usage() {
    cat << EOF
Uso: $0 [opções]

Opções:
  --image <imagem>        Define imagem Docker (padrão: $IMAGE)
  --namespace <nome>      Define namespace Kubernetes (padrão: $NAMESPACE)
  --dry-run               Simula a execução sem aplicar alterações
  --auto                  Executa todas as etapas automaticamente
  --help                  Exibe esta ajuda

Exemplo:
  $0 --image nginx:1.25 --namespace producao --auto

Variáveis de ambiente:
  SLACK_WEBHOOK           Webhook Slack para notificações (obrigatório para alertas)

EOF
    exit 0
}

# -------------------------------
# LOG JSON SIMPLES PARA AUDITORIA
# -------------------------------
log_json() {
    local level=$1
    local message=$2
    local timestamp
    timestamp=$(date --iso-8601=seconds)
    echo "{\"timestamp\":\"$timestamp\",\"level\":\"$level\",\"message\":\"$message\"}"
}

# -------------------------------
# ROLLBACK EM CASO DE ERRO
# -------------------------------
rollback_on_error() {
    log_json "ERROR" "Erro detectado. Iniciando rollback..."
    echo -e "${RED}[ERRO]${RESET} Falha detectada, removendo namespace '$NAMESPACE' para rollback."
    kubectl delete namespace "$NAMESPACE" --ignore-not-found=true || true
    exit 1
}

# -------------------------------
# CHECKS DE AMBIENTE
# -------------------------------
check_root() {
    if [[ $EUID -eq 0 ]]; then
        echo -e "${YELLOW}[AVISO]${RESET} Rodar como root local não é recomendado. Abortando."
        exit 1
    fi
}

check_slack() {
    if [[ -z "$SLACK_WEBHOOK" ]]; then
        log_json "WARN" "Webhook Slack não configurado. Alertas desativados."
    fi
}

notify_slack() {
    local text=$1
    if [[ -n "$SLACK_WEBHOOK" ]]; then
        curl --silent --fail --tlsv1.2 --cacert /etc/ssl/certs/ca-bundle.crt \
            -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"$text\"}" "$SLACK_WEBHOOK" || log_json "WARN" "Falha no envio do alerta Slack"
    fi
}

# -------------------------------
# VALIDAÇÃO DE HASH SHA256 DE BINÁRIOS
# -------------------------------
validate_sha256() {
    local file=$1
    local expected_sha=$2

    if [[ ! -f "$file" ]]; then
        return 1
    fi

    local actual_sha
    actual_sha=$(sha256sum "$file" | awk '{print $1}')
    if [[ "$actual_sha" != "$expected_sha" ]]; then
        return 1
    fi
    return 0
}

# -------------------------------
# INSTALAÇÃO E VERIFICAÇÃO DE DEPENDÊNCIAS
# -------------------------------
install_dependency() {
    local cmd=$1
    log_json "INFO" "Tentando instalar '$cmd'..."

    case $cmd in
        trivy)
            curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
            ;;
        checkov)
            if ! command -v pip &>/dev/null; then
                log_json "ERROR" "pip não encontrado, instale Python3 e pip."
                exit 1
            fi
            pip install --user checkov
            ;;
        cosign)
            local url="https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64"
            local tmp_file="/tmp/cosign"
            curl -sSL "$url" -o "$tmp_file"
            # Exemplo de SHA256 esperado - substituir pelo valor real:
            local expected_sha="3e1c0c0b43c0a12d2d6a7a3f3e29ed94c7f6e8ff3465ff5b0d06f5c1d75b9e1b"
            if ! validate_sha256 "$tmp_file" "$expected_sha"; then
                log_json "ERROR" "Falha na validação SHA256 do Cosign."
                exit 1
            fi
            sudo mv "$tmp_file" /usr/local/bin/cosign
            sudo chmod +x /usr/local/bin/cosign
            ;;
        helm)
            curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
            ;;
        kubectl)
            local version
            version=$(curl -s https://dl.k8s.io/release/stable.txt)
            curl -LO "https://dl.k8s.io/release/${version}/bin/linux/amd64/kubectl"
            sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
            rm kubectl
            ;;
        *)
            log_json "ERROR" "Comando não suportado para instalação: $cmd"
            exit 1
            ;;
    esac
    log_json "INFO" "'$cmd' instalado com sucesso."
}

check_dependencies() {
    log_json "INFO" "Verificando dependências..."
    for cmd in "${REQUIRED_CMDS[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            log_json "WARN" "Dependência '$cmd' não encontrada."
            read -rp "Deseja instalar '$cmd'? (s/n): " opt
            if [[ "$opt" =~ ^[sS]$ ]]; then
                if ! command -v sudo &>/dev/null; then
                    log_json "ERROR" "sudo não encontrado. Instalação manual necessária para '$cmd'."
                    exit 1
                fi
                install_dependency "$cmd"
            else
                log_json "ERROR" "Dependência obrigatória '$cmd' não instalada."
                exit 1
            fi
        else
            local version
            version=$("$cmd" --version 2>&1 | head -n1 || echo "versão desconhecida")
            log_json "INFO" "Dependência '$cmd' encontrada: $version"
        fi
    done
}

# -------------------------------
# FUNCIONALIDADES DE SEGURANÇA E DEPLOY
# -------------------------------
verify_image_signature() {
    log_json "INFO" "Verificando assinatura da imagem Docker com Cosign..."
    $DRY_RUN || cosign verify "$IMAGE" || {
        log_json "ERROR" "Imagem '$IMAGE' não assinada. Execute: cosign sign $IMAGE"
        exit 1
    }
}

scan_image() {
    log_json "INFO" "Executando scan de vulnerabilidades com Trivy..."
    $DRY_RUN || trivy image --severity CRITICAL,HIGH --exit-code 1 "$IMAGE" || {
        log_json "ERROR" "Vulnerabilidades críticas detectadas na imagem."
        exit 1
    }
}

scan_yaml() {
    log_json "INFO" "Verificando YAML com Checkov..."
    $DRY_RUN || checkov -f "$DEPLOY_FILE" --quiet || {
        log_json "WARN" "Problemas detectados no arquivo YAML."
    }
}

apply_security_policies() {
    log_json "INFO" "Aplicando políticas OPA Gatekeeper..."
    $DRY_RUN || {
        helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
        helm repo update
        helm upgrade --install gatekeeper gatekeeper/gatekeeper --namespace gatekeeper-system --create-namespace
        kubectl apply -f "$POLICY_DIR"
    }
}

deploy_falco() {
    log_json "INFO" "Instalando Falco para monitoramento em runtime..."
    $DRY_RUN || {
        helm repo add falcosecurity https://falcosecurity.github.io/charts
        helm repo update
        helm upgrade --install falco falcosecurity/falco --namespace falco --create-namespace
    }
}

deploy_application() {
    log_json "INFO" "Criando namespace e aplicando deployment..."
    $DRY_RUN || {
        kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
        kubectl apply -n "$NAMESPACE" -f "$DEPLOY_FILE"
    }
}

post_deploy_check() {
    log_json "INFO" "Verificando status dos pods no namespace '$NAMESPACE'..."
    sleep 5
    $DRY_RUN || {
        local failed=0
        mapfile -t pods < <(kubectl get pods -n "$NAMESPACE" --no-headers | awk '{print $1, $3}')
        for pod_info in "${pods[@]}"; do
            local pod_name=$(echo "$pod_info" | awk '{print $1}')
            local pod_status=$(echo "$pod_info" | awk '{print $2}')
            if [[ "$pod_status" != "Running" ]]; then
                log_json "WARN" "Pod '$pod_name' com status '$pod_status'."
                ((failed++))
            else
                log_json "INFO" "Pod '$pod_name' está Running."
            fi
        done
        if (( failed > 0 )); then
            notify_slack "Alerta: $failed pods não estão em estado Running no namespace $NAMESPACE."
        fi
    }
}

generate_report() {
    log_json "INFO" "Gerando relatório final..."
    local file="$REPORT_DIR/report_$DATE.html"
    {
        echo "<html><body><h1>Relatório - Deploy Seguro</h1><ul>"
        echo "<li>Aplicação: $APP_NAME</li>"
        echo "<li>Namespace: $NAMESPACE</li>"
        echo "<li>Imagem: $IMAGE</li>"
        echo "<li>Status Pods:</li><pre>$(kubectl get pods -n "$NAMESPACE" 2>/dev/null)</pre>"
        echo "</ul></body></html>"
    } > "$file"
    log_json "INFO" "Relatório salvo em: $file"
}

# -------------------------------
# FUNÇÃO PRINCIPAL
# -------------------------------
main() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --image) shift; IMAGE=$1 ;;
            --namespace) shift; NAMESPACE=$1 ;;
            --dry-run) DRY_RUN=true ;;
            --auto) AUTO_MODE=true ;;
            --help) usage ;;
            *) echo "Parâmetro desconhecido: $1"; usage ;;
        esac
        shift
    done

    banner
    check_root
    check_slack
    check_dependencies

    if $AUTO_MODE; then
        verify_image_signature
        scan_image
        scan_yaml
        apply_security_policies
        deploy_falco
        deploy_application
        post_deploy_check
        generate_report
        log_json "INFO" "Deploy concluído com sucesso."
        notify_slack "Deploy seguro concluído para $APP_NAME no namespace $NAMESPACE."
    else
        echo "Modo interativo ainda não implementado nesta versão."
        exit 0
    fi
}

banner() {
    echo -e "${BLUE}==============================================================="
    echo "      SECURE-K8S-PRO FINAL - Deploy Seguro e Estável"
    echo -e "===============================================================${RESET}"
}

# -------------------------------
# EXECUTA FUNÇÃO PRINCIPAL
# -------------------------------
main "$@"
