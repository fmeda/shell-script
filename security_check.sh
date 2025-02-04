#!/bin/bash

# Função para buscar CVEs de fontes externas
get_cves() {
    # Definindo os sites de busca de CVEs
    cve_sources=(
        "https://cve.mitre.org/"
        "https://nvlpubs.nist.gov/nistpubs/"
        "https://www.securityfocus.com/vulnerabilities"
        "https://www.exploit-db.com/"
        "https://www.circl.lu/services/cve-search/"
        "https://www.vulndb.com/"
        "https://osvdb.org/"
        "https://www.securitytracker.com/"
        "https://seclists.org/fulldisclosure/"
        "https://access.redhat.com/errata"
    )

    echo "Consultando CVEs em fontes externas..."

    # Percorrendo as fontes e fazendo consulta (exemplo de curl, adaptável conforme necessidade)
    for source in "${cve_sources[@]}"; do
        echo "Consultando: $source"
        curl -s "$source" | grep -oP 'CVE-\d{4}-\d+' | sort | uniq
    done
}

# Função para verificar vulnerabilidades relacionadas ao Kernel
check_kernel_vulnerabilities() {
    echo "Verificando vulnerabilidades do Kernel..."
    kernel_version=$(uname -r)
    echo "Versão do Kernel: $kernel_version"

    # Exemplo: Verificar vulnerabilidades conhecidas no Kernel (imaginário)
    if [[ "$kernel_version" =~ "4.15" ]]; then
        echo "Risco: O Kernel 4.15 tem várias vulnerabilidades conhecidas."
        echo "Ação: Atualizar para a versão mais recente do Kernel está recomendado."
    else
        echo "O Kernel parece estar atualizado."
    fi
}

# Função para verificar configurações de SSH
check_ssh_security() {
    echo "Verificando configurações de SSH..."

    # Checar se o SSH está configurado para root login
    ssh_config="/etc/ssh/sshd_config"
    root_login=$(grep "^PermitRootLogin" "$ssh_config")

    if [[ "$root_login" == "PermitRootLogin yes" ]]; then
        echo "Risco: O login direto como root via SSH está habilitado."
        echo "Ação: Desabilitar o login de root em /etc/ssh/sshd_config."
        echo "Alterar para: PermitRootLogin no"
    else
        echo "A configuração de SSH parece segura."
    fi
}

# Função para gerar relatório
generate_report() {
    echo "Gerando relatório de segurança..."
    report_file="security_report_$(date +'%Y-%m-%d_%H-%M-%S').txt"
    echo "Relatório de Segurança - $(date)" > "$report_file"
    echo "---------------------------------------" >> "$report_file"
    
    echo "Consultando fontes de CVEs..." >> "$report_file"
    get_cves >> "$report_file"
    
    echo "---------------------------------------" >> "$report_file"
    check_kernel_vulnerabilities >> "$report_file"
    
    echo "---------------------------------------" >> "$report_file"
    check_ssh_security >> "$report_file"
    
    echo "Relatório gerado com sucesso em $report_file"
}

# Executar a geração do relatório
generate_report
