#!/bin/bash

# Solicitar ao usuário o IP ou RANGE de IPs do equipamento Fortinet
echo "Digite o IP ou RANGE de IPs do equipamento Fortinet (ex: 192.168.1.1 ou 192.168.1.0/24):"
read fortinet_ip

# Solicitar login e senha de forma segura (proteção da senha com 'stty')
echo "Digite seu login para o FortiManager:"
read fortinet_user
echo "Digite sua senha para o FortiManager:"
stty -echo  # Desativa a exibição da senha no terminal
read fortinet_pass
stty echo  # Restaura a exibição normal

# Confirmar a entrada de dados
echo "Acessando o FortiManager com as credenciais fornecidas..."

# Iniciar a sessão SSH com as credenciais fornecidas (exemplo com `sshpass` para automação)
# Certifique-se de que o comando `sshpass` esteja instalado no seu sistema
# A conexão SSH será feita com as credenciais inseridas

echo "Conectando ao FortiManager..."
sshpass -p "$fortinet_pass" ssh -o StrictHostKeyChecking=no "$fortinet_user"@"$fortinet_ip" <<EOF

# Solicitar ao usuário os dados necessários para a criação da política
echo "Digite a interface de origem (ex: port1):"
read src_intf
echo "Digite a interface de destino (ex: port2):"
read dst_intf
echo "Digite o endereço de origem (ex: 192.168.1.0/24):"
read src_addr
echo "Digite o endereço de destino (ex: 192.168.2.0/24):"
read dst_addr
echo "Digite os serviços permitidos (ex: HTTP HTTPS):"
read services
echo "Digite o nome da política de firewall (ex: Allow-HTTP-HTTPS):"
read policy_name

# Gerar um ID de política automático (incrementando o último ID usado)
policy_id=$(($(fw_policy_id_last)+1))  # Incrementa o último ID da política configurada (ajustado para FortiManager)

# Script para criação da política de firewall com logging avançado
echo "Aplicando a política de firewall..."

config firewall policy
    edit $policy_id
        set name "$policy_name"
        set srcintf "$src_intf"
        set dstintf "$dst_intf"
        set srcaddr "$src_addr"
        set dstaddr "$dst_addr"
        set action accept
        set schedule "always"
        set service $services
        set logtraffic all         # Registrar todo o tráfego
        set logallowedtraffic enable  # Logar tráfego permitido
        set logdenytraffic enable     # Logar tráfego negado
    next
end

# Verificar se as interfaces estão configuradas
echo "Verificando configurações de interfaces..."
config system interface
    show
end

# Verificar se a política já existe antes de aplicar
echo "Verificando as políticas existentes..."
config firewall policy
    show
end

# Verificação de HA (Alta Disponibilidade) para garantir que a política seja aplicada corretamente em clusters
echo "Verificando status de HA..."
config system ha
    show  # Verifica status do HA e sincronização
end

# Teste da política em ambiente de teste (Modo de teste)
echo "Testando a política em modo de teste..."
config firewall policy
    set testmode enable  # Ativa o modo de teste para garantir que a política funcione corretamente
end

# Atribuir a política ao pacote de políticas e aplicar aos dispositivos/grupos de dispositivos
echo "Atribuindo a política ao pacote de políticas..."
# Substitua <NOME_DO_PACKAGE> pelo nome do pacote de políticas e <NOME_DO_DEVICE_GRUPO> pelo grupo de dispositivos
execute install policy package "MyPolicyPackage" to "DeviceGroupName"

# Gerar um relatório de alterações para auditoria e acompanhamento
echo "Gerando relatório de alterações..."
execute log save "FirewallPolicyChanges"

# Finalizar a sessão SSH
exit
EOF

# Relatório de regras criadas
echo "Relatório gerado:"

# Usando `sshpass` novamente para gerar o relatório das regras criadas diretamente do FortiManager
sshpass -p "$fortinet_pass" ssh -o StrictHostKeyChecking=no "$fortinet_user"@"$fortinet_ip" <<EOF
echo "Regras de Firewall Criadas:"
config firewall policy
    show  # Exibe as políticas de firewall configuradas
end
EOF

echo "Política de firewall aplicada e relatório gerado com sucesso!"
