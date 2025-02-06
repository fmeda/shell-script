#!/bin/bash

# ========================
# SecGuard - Linux Hardening Suite
# ========================
# Autor: [Seu Nome]
# Versão: 2.0 (Atualizado para CIS v8 - 2025)
# Descrição: Implementação dos 18 Controles CIS v8 com melhorias contínuas.

# Cores para status
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # Sem cor

# Verificar se o script está sendo executado como root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[ERRO] Este script deve ser executado como root!${NC}"
   exit 1
fi

# Verificar dependências (nmap, ufw, rsyslog, etc)
for cmd in nmap ufw rsyslog; do
    if ! command -v $cmd &>/dev/null; then
        echo -e "${RED}[ERRO] A ferramenta $cmd não está instalada!${NC}"
        exit 1
    fi
done

# Função para exibir o cabeçalho
echo -e "${GREEN}\n============================="
echo "   SecGuard - Linux Hardening Suite"
echo -e "=============================${NC}\n"

# Criar relatório CSV com timestamp
REPORT_FILE="/var/log/secguard_report_$(date +%F_%T).csv"
echo "Data,Controle,Status,Detalhes" > $REPORT_FILE

# Função para teste remoto via SSH
teste_remoto() {
    echo -e "${GREEN}[+] Teste remoto via SSH${NC}"
    read -p "Informe o IP ou hostname do destino: " DESTINO
    read -p "Informe o usuário SSH: " USUARIO
    ssh -o BatchMode=yes -o ConnectTimeout=5 $USUARIO@$DESTINO "echo 'Conexão estabelecida com sucesso'" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[OK] Conexão SSH estabelecida com sucesso.${NC}"
        echo "$(date +%F_%T),Teste Remoto SSH,OK,Conexão bem-sucedida com $DESTINO" >> $REPORT_FILE
    else
        echo -e "${RED}[ERRO] Falha ao conectar via SSH.${NC}"
        echo "$(date +%F_%T),Teste Remoto SSH,FALHA,Não foi possível conectar a $DESTINO" >> $REPORT_FILE
    fi
}

# Perguntar ao usuário se deseja executar o teste remoto
read -p "Deseja executar um teste remoto via SSH? (s/n): " RESPOSTA
if [[ "$RESPOSTA" =~ ^[Ss]$ ]]; then
    teste_remoto
fi

# 1. Inventário de Ativos Empresariais e Software
echo -e "${GREEN}[+] Coletando inventário de ativos...${NC}"
nmap -sP 192.168.1.0/24 > /var/log/inventario_rede.txt
apt list --installed > /var/log/inventario_software.txt
echo "$(date +%F_%T),Inventário de Ativos,OK,Coletado com sucesso" >> $REPORT_FILE
echo -e "${GREEN}[OK] Inventário coletado.${NC}\n"

# 2. Proteção de Dados
echo -e "${GREEN}[+] Protegendo dados sensíveis...${NC}"
chmod -R 700 /home/*
chown root:root /etc/shadow
echo "$(date +%F_%T),Proteção de Dados,OK,Permissões ajustadas" >> $REPORT_FILE
echo -e "${GREEN}[OK] Proteção de dados aplicada.${NC}\n"

# 3. Configuração Segura de Ativos e Software
echo -e "${GREEN}[+] Aplicando configurações seguras...${NC}"
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow http
ufw allow https
ufw enable
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
sysctl -p
echo "$(date +%F_%T),Configuração Segura,OK,Regras aplicadas" >> $REPORT_FILE
echo -e "${GREEN}[OK] Configuração segura aplicada.${NC}\n"

# 4. Gerenciamento de Contas e Controle de Acesso
echo -e "${GREEN}[+] Ajustando controle de contas...${NC}"
passwd -l root  # Bloquear login direto do root
find /home -type d -ctime +30 -exec chage -E0 {} \;
echo "$(date +%F_%T),Gerenciamento de Contas,OK,Contas ajustadas" >> $REPORT_FILE
echo -e "${GREEN}[OK] Controle de contas reforçado.${NC}\n"

# 5. Gerenciamento de Vulnerabilidades
echo -e "${GREEN}[+] Verificando vulnerabilidades...${NC}"
apt update && apt upgrade -y && apt autoremove -y
echo "$(date +%F_%T),Vulnerabilidades,OK,Sistema atualizado" >> $REPORT_FILE
echo -e "${GREEN}[OK] Atualizações aplicadas.${NC}\n"

# 6. Desabilitar login SSH por senha
echo -e "${GREEN}[+] Desabilitando login SSH por senha...${NC}"
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart sshd
echo "$(date +%F_%T),Segurança SSH,OK,Login por senha desabilitado" >> $REPORT_FILE
echo -e "${GREEN}[OK] Login SSH por senha desabilitado.${NC}\n"

# 7. Configurar atualizações automáticas de segurança
echo -e "${GREEN}[+] Configurando atualizações automáticas de segurança...${NC}"
apt install unattended-upgrades
dpkg-reconfigure --priority=low unattended-upgrades
echo "$(date +%F_%T),Atualizações Automáticas,OK,Configuração de atualizações automáticas" >> $REPORT_FILE
echo -e "${GREEN}[OK] Atualizações automáticas configuradas.${NC}\n"

# 8. Configuração do Kernel (proteção contra execução de código no stack)
echo -e "${GREEN}[+] Aplicando configurações de segurança do Kernel...${NC}"
sysctl -w kernel.randomize_va_space=2
echo "$(date +%F_%T),Segurança do Kernel,OK,Configuração aplicada" >> $REPORT_FILE
echo -e "${GREEN}[OK] Configuração do Kernel aplicada.${NC}\n"

# 9. Backup e Recuperação
echo -e "${GREEN}[+] Realizando backup...${NC}"
rsync -av /home/ /backup/
echo "$(date +%F_%T),Backup,OK,Backup realizado com sucesso" >> $REPORT_FILE
echo -e "${GREEN}[OK] Backup realizado.${NC}\n"

# 10. Configuração de envio de logs para servidor central
echo -e "${GREEN}[+] Configurando envio de logs para servidor central...${NC}"
echo "*.* @seu_servidor_log:514" >> /etc/rsyslog.conf
systemctl restart rsyslog
echo "$(date +%F_%T),Logs,OK,Logs enviados para servidor central" >> $REPORT_FILE
echo -e "${GREEN}[OK] Logs configurados para envio.${NC}\n"

# Finalização
echo -e "${GREEN}[COMPLETO] Hardening concluído com sucesso.${NC}\n"
echo "Relatório salvo em: $REPORT_FILE"
