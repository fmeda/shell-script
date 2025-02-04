#!/bin/bash

# Nome do Script: linux_hardening.sh
# Descrição: Script para aplicar práticas de hardening em um sistema Linux
# Versão: 1.0
# Autor: [Seu Nome]

# Função para instalar pacotes necessários
install_packages() {
    echo "Instalando pacotes necessários..."
    # Instala pacotes de auditoria e segurança
    apt-get update -y
    apt-get install -y lynis chkrootkit rkhunter ufw auditd nmap

    # Verifica a instalação bem-sucedida
    echo "Pacotes instalados com sucesso!"
}

# Função para auditar o sistema com Lynis
audit_system() {
    echo "Iniciando auditoria com Lynis..."
    lynis audit system
}

# Função para verificar serviços e desativar desnecessários
disable_services() {
    echo "Desabilitando serviços desnecessários..."
    systemctl stop apache2
    systemctl disable apache2
    systemctl stop mysql
    systemctl disable mysql
    systemctl stop postfix
    systemctl disable postfix

    # Verifica se serviços indesejados foram desabilitados
    systemctl list-units --type=service --state=running
}

# Função para configurar SSH para desabilitar login como root
configure_ssh() {
    echo "Configurando SSH para desabilitar login de root..."
    sed -i 's/^#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    systemctl restart sshd

    # Verifica se a configuração foi aplicada
    grep "PermitRootLogin" /etc/ssh/sshd_config
}

# Função para aplicar regras de firewall (UFW)
configure_firewall() {
    echo "Configurando Firewall (UFW)..."
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw enable

    # Verifica o status do firewall
    ufw status
}

# Função para configurar políticas de senha
configure_password_policy() {
    echo "Configurando políticas de senha..."
    # Configura as regras de senha no PAM
    echo "password requisite pam_pwquality.so retry=3 minlen=8 difok=3" >> /etc/pam.d/common-password

    # Verifica configurações
    cat /etc/pam.d/common-password | grep pam_pwquality
}

# Função para auditar rootkits com chkrootkit e rkhunter
check_rootkits() {
    echo "Verificando rootkits com chkrootkit e rkhunter..."
    chkrootkit
    rkhunter --check

    # Verifica se há alertas
    tail -n 10 /var/log/rkhunter.log
    tail -n 10 /var/log/chkrootkit.log
}

# Função para executar verificação de pacotes desatualizados
check_system_updates() {
    echo "Verificando pacotes desatualizados..."
    apt-get update -y
    apt-get upgrade -y

    # Verifica se o sistema está atualizado
    dpkg -l | grep '^ii' | awk '{print $2, $3}'
}

# Função para auditar configurações de segurança do sistema
audit_security_settings() {
    echo "Iniciando auditoria de segurança..."
    # Verificar configurações de senha e usuários
    awk -F: '($2 == "" ) {print $1}' /etc/shadow

    # Verificar usuários com UID 0 (root)
    awk -F: '$3 == 0 {print $1}' /etc/passwd
}

# Função para configurar o auditd para monitoramento de segurança
configure_auditd() {
    echo "Configurando o auditd para monitoramento de segurança..."
    systemctl enable auditd
    systemctl start auditd

    # Verifica status do auditd
    systemctl status auditd
}

# Função principal que chama todas as etapas de hardening
hardening_process() {
    install_packages
    audit_system
    disable_services
    configure_ssh
    configure_firewall
    configure_password_policy
    check_rootkits
    check_system_updates
    audit_security_settings
    configure_auditd

    echo "Hardening do sistema Linux completado com sucesso!"
}

# Executa o processo de hardening
hardening_process
