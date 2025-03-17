#!/bin/bash

# --------------------------------------------------------
# Função para validar a presença de parâmetros obrigatórios
validate_params() {
  if [[ -z "$1" ]]; then
    echo "Erro: Parâmetro obrigatório não fornecido."
    exit 1
  fi
}

# --------------------------------------------------------
# Função para configurar logging e rotação de logs
setup_logging() {
  log_event "Configuração iniciada"
  logrotate -f /etc/logrotate.conf
}

# --------------------------------------------------------
# Função para logar eventos com timestamp
log_event() {
  local event="$1"
  echo "$(date "+%Y-%m-%d %H:%M:%S") - $event" >> /var/log/script_secure_run.log
}

# --------------------------------------------------------
# Função para verificar se o Docker está instalado
check_docker() {
  if ! command -v docker &> /dev/null; then
    echo "Docker não encontrado. Instalando..."
    sudo apt-get update && sudo apt-get install -y docker.io
  else
    echo "Docker já instalado."
  fi
}

# --------------------------------------------------------
# Função para verificar se o Ansible está instalado
check_ansible() {
  if ! command -v ansible &> /dev/null; then
    echo "Ansible não encontrado. Instalando..."
    sudo apt-get update && sudo apt-get install -y ansible
  else
    echo "Ansible já instalado."
  fi
}

# --------------------------------------------------------
# Função para verificar se o Kubernetes (kubectl) está instalado
check_kubernetes() {
  if ! command -v kubectl &> /dev/null; then
    echo "kubectl não encontrado. Instalando..."
    curl -LO https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl
    chmod +x ./kubectl
    sudo mv ./kubectl /usr/local/bin/kubectl
  else
    echo "kubectl já instalado."
  fi
}

# --------------------------------------------------------
# Função para configurar segurança do Docker
secure_docker() {
  echo "Configurando segurança do Docker..."
  sudo systemctl stop docker
  sudo systemctl disable docker
  sudo sed -i 's|^# DOCKER_OPTS=.*|DOCKER_OPTS="--host=unix:///var/run/docker.sock"|' /etc/default/docker
  sudo systemctl start docker
  log_event "Segurança do Docker configurada"
}

# --------------------------------------------------------
# Função para configurar segurança do Ansible
secure_ansible() {
  echo "Configurando segurança do Ansible..."
  sudo chmod 700 /etc/ansible
  sudo chmod 600 /etc/ansible/hosts
  log_event "Segurança do Ansible configurada"
}

# --------------------------------------------------------
# Função para configurar segurança do Kubernetes
secure_kubernetes() {
  echo "Configurando segurança do Kubernetes..."
  kubectl apply -f rbac-configuration.yaml
  log_event "Segurança do Kubernetes configurada"
}

# --------------------------------------------------------
# Função para realizar backup de configurações críticas antes da execução
backup_configurations() {
  echo "Realizando backup de configurações críticas..."
  # Exemplo de backup de arquivos do Docker, Ansible e Kubernetes
  tar -czf /var/backups/docker_config_backup.tar.gz /etc/docker/
  tar -czf /var/backups/ansible_config_backup.tar.gz /etc/ansible/
  kubectl get all --all-namespaces -o yaml > /var/backups/kubernetes_backup.yaml
  log_event "Backup de configurações realizado"
}

# --------------------------------------------------------
# Função para realizar a verificação de vulnerabilidades com Trivy
check_vulnerabilities() {
  echo "Verificando vulnerabilidades com Trivy..."
  # Baixar e verificar vulnerabilidades em imagens Docker
  trivy image --no-progress --exit-code 1 --severity HIGH,CRITICAL nginx:latest
  if [[ $? -ne 0 ]]; then
    echo "Vulnerabilidades críticas encontradas!"
    exit 1
  else
    echo "Nenhuma vulnerabilidade crítica encontrada."
  fi
  log_event "Verificação de vulnerabilidades concluída"
}

# --------------------------------------------------------
# Função para configurar o Wazuh para monitoramento de anomalias
setup_wazuh_monitoring() {
  echo "Configurando Wazuh para monitoramento de anomalias..."
  # Supõe-se que o Wazuh já esteja instalado e configurado no ambiente
  # Caso contrário, deve-se instalar e configurar
  sudo systemctl start wazuh-manager
  sudo systemctl enable wazuh-manager
  log_event "Monitoramento com Wazuh configurado"
}

# --------------------------------------------------------
# Função para executar o Docker de forma segura
execute_docker_secure() {
  echo "Iniciando contêiner Docker com segurança..."
  docker run --read-only --no-new-privileges --user $(id -u):$(id -g) --security-opt seccomp=default.json --cap-drop=ALL --cap-add=NET_BIND_SERVICE nginx
  log_event "Contêiner Docker iniciado com segurança"
}

# --------------------------------------------------------
# Função para executar o Ansible de forma segura
execute_ansible_secure() {
  echo "Executando playbook Ansible com segurança..."
  ansible-playbook --check --diff --limit 'production' site.yml
  log_event "Playbook Ansible executado com segurança"
}

# --------------------------------------------------------
# Função para executar o Kubernetes de forma segura
execute_kubernetes_secure() {
  echo "Iniciando pod Kubernetes com segurança..."
  kubectl run mypod --image=nginx --security-context='{"runAsUser":1000,"runAsGroup":1000,"runAsNonRoot":true}'
  log_event "Pod Kubernetes iniciado com segurança"
}

# --------------------------------------------------------
# Função para revisar logs de segurança
review_logs() {
  echo "Revisando logs de segurança..."
  tail -n 100 /var/log/syslog
  log_event "Logs de segurança revisados"
}

# --------------------------------------------------------
# Função para realizar limpeza pós-execução
cleanup() {
  echo "Realizando limpeza pós-execução..."
  docker system prune -f
  kubectl delete pods --all
  log_event "Limpeza pós-execução realizada"
}

# --------------------------------------------------------
# Função principal para execução do script
main() {
  validate_params "$1"  # Validação de parâmetros

  setup_logging  # Configuração de logging
  log_event "Iniciando execução do script"

  # Realizar backup de configurações críticas
  backup_configurations

  # Verificação de vulnerabilidades com Trivy
  check_vulnerabilities

  # Verificação de pré-requisitos
  check_docker
  check_ansible
  check_kubernetes

  # Configuração de segurança
  secure_docker
  secure_ansible
  secure_kubernetes

  # Configuração do Wazuh para monitoramento de anomalias
  setup_wazuh_monitoring

  # Execução segura
  execute_docker_secure
  execute_ansible_secure
  execute_kubernetes_secure

  # Revisão de logs e limpeza pós-execução
  review_logs
  cleanup

  log_event "Execução do script concluída com sucesso"
}

# --------------------------------------------------------
# Chama a função principal
main "$1"
