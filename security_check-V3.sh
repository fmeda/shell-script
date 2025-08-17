#!/bin/bash
# =============================================================================
# Nome: ProdSecurityAudit.sh
# Descrição: Auditoria completa de segurança para Linux em ambientes de produção.
# Autor: [Seu Nome]
# Versão: 3.0 (2025)
# Licença: GPLv3
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# -----------------------------------
# Funções de Log
# -----------------------------------
log_info()    { echo -e "[INFO]    $*"; }
log_warn()    { echo -e "[WARNING] $*"; }
log_error()   { echo -e "[ERROR]   $*" >&2; }

# -----------------------------------
# Variáveis Globais
# -----------------------------------
REPORT_JSON=""
CHECK_LIST=()

# -----------------------------------
# Função --help
# -----------------------------------
show_help() {
cat << EOF
Uso: $0 [OPÇÕES]

Opções:
  --help                Exibe este menu de ajuda
  --output <arquivo>    Define o arquivo de saída (JSON/CSV)
  --check <itens>       Itens a verificar (cve,ssh,kernel,packages,services)
EOF
exit 0
}

# -----------------------------------
# Função para baixar CVEs de fontes confiáveis
# -----------------------------------
get_cves() {
    log_info "Consultando CVEs em fontes externas..."
    local cve_sources=(
        "https://cve.mitre.org/"
        "https://nvd.nist.gov/vuln/search/results"
    )

    local cve_list=()
    for source in "${cve_sources[@]}"; do
        log_info "Consultando: $source"
        if curl -fsSL --max-time 10 "$source" > /dev/null; then
            # Extraindo CVEs (regex genérico)
            cve_list+=($(curl -fsSL "$source" | grep -oP 'CVE-\d{4}-\d+' | sort | uniq))
        else
            log_warn "Não foi possível acessar $source"
        fi
    done
    echo "${cve_list[@]}" | sort | uniq
}

# -----------------------------------
# Função para verificar vulnerabilidades do Kernel
# -----------------------------------
check_kernel_vulnerabilities() {
    log_info "Verificando vulnerabilidades do Kernel..."
    local kernel_version
    kernel_version=$(uname -r)
    log_info "Versão do Kernel: $kernel_version"

    # Exemplo simplificado: comparar com CVEs conhecidas
    local vulnerable_kernels=("4.15" "4.18")
    for ver in "${vulnerable_kernels[@]}"; do
        if [[ "$kernel_version" =~ "$ver" ]]; then
            log_warn "Kernel $kernel_version com vulnerabilidades conhecidas!"
            echo "Ação recomendada: Atualizar para versão estável mais recente."
        fi
    done
}

# -----------------------------------
# Função para verificar configurações SSH
# -----------------------------------
check_ssh_security() {
    log_info "Verificando configurações SSH..."
    local ssh_config="/etc/ssh/sshd_config"

    if [[ ! -r "$ssh_config" ]]; then
        log_warn "Arquivo $ssh_config não pode ser lido."
        return
    fi

    local root_login
    root_login=$(grep "^PermitRootLogin" "$ssh_config" || echo "")

    if [[ "$root_login" == "PermitRootLogin yes" ]]; then
        log_warn "Login root via SSH habilitado!"
        echo "Ação: Modificar para PermitRootLogin no"
    else
        log_info "SSH configurado corretamente."
    fi
}

# -----------------------------------
# Função para checar pacotes críticos
# -----------------------------------
check_packages() {
    log_info "Verificando pacotes críticos instalados..."
    local packages=("openssl" "sudo" "bash" "curl" "openssh-server")
    for pkg in "${packages[@]}"; do
        if ! dpkg -l | grep -q "$pkg"; then
            log_warn "Pacote $pkg não está instalado!"
        else
            log_info "Pacote $pkg presente."
        fi
    done
}

# -----------------------------------
# Função para checar serviços ativos
# -----------------------------------
check_services() {
    log_info "Verificando serviços críticos..."
    local services=("ssh" "cron" "ufw" "docker")
    for svc in "${services[@]}"; do
        if systemctl is-active --quiet "$svc"; then
            log_info "Serviço $svc ativo."
        else
            log_warn "Serviço $svc inativo!"
        fi
    done
}

# -----------------------------------
# Função para gerar relatório JSON
# -----------------------------------
generate_report() {
    local report_file="${REPORT_JSON:-security_report_$(date +'%Y-%m-%d_%H-%M-%S').json}"
    log_info "Gerando relatório em $report_file"

    {
        echo "{"
        echo "  \"data_execucao\": \"$(date)\","
        echo "  \"kernel\": \"$(uname -r)\","
        echo "  \"ssh_config\": \"$(grep '^PermitRootLogin' /etc/ssh/sshd_config || echo 'não encontrado')\","
        echo "  \"cves_encontradas\": ["
        local cves
        cves=$(get_cves)
        for cve in $cves; do
            echo "    \"$cve\","
        done
        echo "  ]"
        echo "}"
    } > "$report_file"

    log_info "Relatório gerado com sucesso."
}

# -----------------------------------
# Parse de parâmetros CLI
# -----------------------------------
while [[ $# -gt 0 ]]; do
    case $1 in
        --help) show_help ;;
        --output) REPORT_JSON="$2"; shift 2 ;;
        --check) IFS=',' read -r -a CHECK_LIST <<< "$2"; shift 2 ;;
        *) log_error "Parâmetro inválido: $1"; show_help ;;
    esac
done

# Se CHECK_LIST vazio, rodar todos
[[ ${#CHECK_LIST[@]} -eq 0 ]] && CHECK_LIST=("cve" "ssh" "kernel" "packages" "services")

# -----------------------------------
# Execução das verificações
# -----------------------------------
for check in "${CHECK_LIST[@]}"; do
    case $check in
        cve) get_cves ;;
        ssh) check_ssh_security ;;
        kernel) check_kernel_vulnerabilities ;;
        packages) check_packages ;;
        services) check_services ;;
        *) log_warn "Check desconhecido: $check" ;;
    esac
done

# Geração final do relatório
generate_report
