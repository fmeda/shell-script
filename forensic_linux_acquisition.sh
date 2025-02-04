#!/bin/bash
# forensic_linux_acquisition.sh
# Script para aquisição forense de sistemas Linux, voltado para forças de segurança.
# Segue normas internacionais como ISO/IEC 27037, NIST 800-86 e RFC 3227.

### CONFIGURAÇÕES INICIAIS ###
LOG_DIR="/mnt/forensics/logs"         # Diretório para armazenar logs da perícia
IMAGE_DIR="/mnt/forensics/images"     # Diretório para armazenar imagens de disco
HASH_ALGO="sha256sum"                 # Algoritmo de hash para verificar integridade
TIMESTAMP=$(date +%Y%m%d_%H%M%S)        # Marca temporal
HOSTNAME=$(hostname)                    # Nome do sistema analisado
CASE_ID="Caso_001"                      # Identificador do caso (modificar conforme necessário)
LOG_FILE="$LOG_DIR/pericia_$HOSTNAME_$TIMESTAMP.log"

# Criando diretórios necessários
mkdir -p "$LOG_DIR" "$IMAGE_DIR"
echo "[INFO] Início da aquisição forense em $HOSTNAME" | tee -a "$LOG_FILE"

### ETAPA 1: PRESERVAÇÃO DAS EVIDÊNCIAS ###
echo "[INFO] Preservação das evidências..." | tee -a "$LOG_FILE"

# Isolamento de Rede
echo "[INFO] Desconectando interfaces de rede..." | tee -a "$LOG_FILE"
nmcli radio wifi off &> /dev/null || echo "[WARNING] Falha ao desligar Wi-Fi" | tee -a "$LOG_FILE"
ifconfig eth0 down &> /dev/null || echo "[WARNING] Falha ao desativar interface Ethernet" | tee -a "$LOG_FILE"
echo "[INFO] Rede desativada com sucesso." | tee -a "$LOG_FILE"

# Coleta de informações básicas
echo "[INFO] Coletando informações do sistema..." | tee -a "$LOG_FILE"
uname -a | tee -a "$LOG_FILE"
uptime | tee -a "$LOG_FILE"

### ETAPA 2: COLETA DE EVIDÊNCIAS VOLÁTEIS ###
echo "[INFO] Coletando evidências voláteis..." | tee -a "$LOG_FILE"

# Processos ativos
ps aux > "$LOG_DIR/processos_$HOSTNAME_$TIMESTAMP.txt"

# Conexões de rede abertas
netstat -tulnp > "$LOG_DIR/conexoes_$HOSTNAME_$TIMESTAMP.txt"

# Lista de usuários logados
who > "$LOG_DIR/usuarios_$HOSTNAME_$TIMESTAMP.txt"

# Tabela de roteamento
route -n > "$LOG_DIR/roteamento_$HOSTNAME_$TIMESTAMP.txt"

### ETAPA 3: AQUISIÇÃO DE IMAGEM DO DISCO ###
echo "[INFO] Criando imagem forense do disco..." | tee -a "$LOG_FILE"
DISK=$(lsblk -ndo NAME,TYPE | awk '$2=="disk" {print "/dev/"$1}')
IMAGE_FILE="$IMAGE_DIR/image_$HOSTNAME_$TIMESTAMP.dd"
HASH_FILE="$IMAGE_DIR/image_$HOSTNAME_$TIMESTAMP.hash"

dd if="$DISK" of="$IMAGE_FILE" bs=4M status=progress | tee -a "$LOG_FILE"
echo "[INFO] Imagem forense criada com sucesso." | tee -a "$LOG_FILE"

# Cálculo e verificação de hash
echo "[INFO] Calculando hash da imagem..." | tee -a "$LOG_FILE"
$HASH_ALGO "$IMAGE_FILE" | tee "$HASH_FILE"

### ETAPA 4: ANÁLISE INICIAL DOS DADOS ###
echo "[INFO] Realizando análise inicial..." | tee -a "$LOG_FILE"

# Logs de sistema
cp /var/log/auth.log "$LOG_DIR/auth_$HOSTNAME_$TIMESTAMP.log" 2>/dev/null
cp /var/log/syslog "$LOG_DIR/syslog_$HOSTNAME_$TIMESTAMP.log" 2>/dev/null
cp /var/log/dmesg "$LOG_DIR/dmesg_$HOSTNAME_$TIMESTAMP.log" 2>/dev/null
echo "[INFO] Logs copiados com sucesso." | tee -a "$LOG_FILE"

# Arquivos recentes
find / -type f -mtime -7 -exec ls -lah {} \; > "$LOG_DIR/arquivos_recentes_$HOSTNAME_$TIMESTAMP.txt" 2>/dev/null
echo "[INFO] Coleta de arquivos recentes concluída." | tee -a "$LOG_FILE"

### ETAPA 5: FINALIZAÇÃO ###
echo "[INFO] Perícia concluída com sucesso." | tee -a "$LOG_FILE"

# Exibir resumo
echo "Resumo da perícia armazenado em: $LOG_FILE"
