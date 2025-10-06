#!/usr/bin/env bash
# ================================================================
# SentinelOS Full Enterprise Installer v1.0
# Autor: Fabiano Aparecido
# Objetivo: Instalação completa SentinelOS + Guard + ML
# ================================================================

LOG_FILE="/var/log/sentinelos_full.log"
INSTALL_HOME="/opt/sentinelos"
GUARD_HOME="$INSTALL_HOME/guard"
ML_HOME="$INSTALL_HOME/ml"

DETECTION_INTERVAL=60
KERNEL_VERSION="6.8-hardened"
DEBIAN_FRONTEND=noninteractive

GREEN="\e[32m"; RED="\e[31m"; BLUE="\e[34m"; NC="\e[0m"

# --- UTILITÁRIOS ---
log() {
  echo -e "${BLUE}[*]${NC} $1"
  echo "$(date '+%F %T') - $1" >> "$LOG_FILE"
}

check_root() {
  if [[ "$EUID" -ne 0 ]]; then
    echo -e "${RED}[ERRO]${NC} Execute como root."
    exit 1
  fi
}

banner() {
  echo -e "${GREEN}"
  echo "===================================================="
  echo " SentinelOS Full Enterprise Installer v1.0"
  echo "===================================================="
  echo -e "${NC}"
}

# --- DEPENDÊNCIAS BASE ---
install_dependencies() {
  log "Instalando dependências essenciais..."
  apt update -y && apt upgrade -y
  apt install -y curl wget git ufw apparmor apparmor-utils fail2ban gnupg lsb-release \
                 linux-headers-$(uname -r) auditd lynis unattended-upgrades \
                 clamav clamav-daemon tor privoxy haveged chkrootkit rkhunter \
                 python3 python3-pip jq tcpdump
  pip3 install --upgrade pip
  pip3 install tensorflow tensorflow-lite numpy pandas scapy
}

# --- KERNEL HARDENED ---
install_hardened_kernel() {
  log "Instalando kernel hardened..."
  apt install -y linux-image-$KERNEL_VERSION || log "Kernel Hardened já instalado ou indisponível."
}

# --- FIREWALL + HARDENING ---
configure_firewall() {
  log "Configurando firewall UFW e Fail2ban..."
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow ssh
  ufw enable
  systemctl enable ufw
  systemctl enable fail2ban
}

run_hardening() {
  log "Executando hardening avançado..."
  lynis audit system --quiet
  sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
  sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
  systemctl restart ssh
  echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
  echo "fs.protected_hardlinks = 1" >> /etc/sysctl.conf
  echo "fs.protected_symlinks = 1" >> /etc/sysctl.conf
  sysctl -p
}

# --- PRIVACIDADE ---
install_privacy_tools() {
  log "Instalando ferramentas de privacidade..."
  apt install -y tor privoxy bleachbit secure-delete
  systemctl enable tor
  systemctl enable privoxy
}

# --- SANDBOX ---
install_sandbox() {
  log "Instalando sandbox..."
  apt install -y firejail bubblewrap
  echo "alias safe-browser='firejail --noprofile firefox'" >> /etc/bash.bashrc
}

# --- CRIPTOGRAFIA ---
setup_encryption() {
  log "Configurando criptografia..."
  apt install -y cryptsetup
  echo "export HISTCONTROL=ignoreboth:erasedups" >> /etc/profile
}

# --- SENTINEL GUARD ---
install_sentinel_guard() {
  log "Instalando Sentinel Guard..."
  mkdir -p "$GUARD_HOME"
  cat << 'EOF' > "$GUARD_HOME/sentinel_guard.sh"
#!/usr/bin/env bash
LOG_FILE="/var/log/sentinel_guard.log"
GUARD_HOME="/opt/sentinelos/guard"
THREAT_LIST="$GUARD_HOME/threats.txt"
AI_DB="$GUARD_HOME/anomalies.db"
DETECTION_INTERVAL=60
CPU_THRESHOLD=85
MEM_THRESHOLD=90
mkdir -p "$GUARD_HOME"
touch "$AI_DB" "$THREAT_LIST"
log() { echo -e "[*] $1"; echo "$(date '+%F %T') - $1" >> "$LOG_FILE"; }
block_offender() {
  local reason="$1"
  local offenders=$(ss -tunap | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -3 | awk '{print $2}')
  for ip in $offenders; do
    if ! grep -q "$ip" "$THREAT_LIST"; then
      ufw deny from "$ip"
      echo "$ip" >> "$THREAT_LIST"
      log "IP bloqueado: $ip (motivo: $reason)"
    fi
  done
}
main() {
  log "Sentinel Guard ativo"
  while true; do
    CPU=$(top -bn1 | grep "Cpu(s)" | awk '{print 100 - $8}')
    MEM=$(free | grep Mem | awk '{print $3/$2 * 100.0}')
    (( ${CPU%.*} > CPU_THRESHOLD )) && block_offender "CPU"
    (( ${MEM%.*} > MEM_THRESHOLD )) && block_offender "MEM"
    sleep $DETECTION_INTERVAL
  done
}
main
EOF
  chmod +x "$GUARD_HOME/sentinel_guard.sh"
}

# --- SENTINEL ML ---
install_sentinel_ml() {
  log "Instalando Sentinel ML..."
  mkdir -p "$ML_HOME"
  cat << 'EOF' > "$ML_HOME/sentinel_ml.sh"
#!/usr/bin/env bash
ML_HOME="/opt/sentinelos/ml"
LOG_FILE="/var/log/sentinel_ml.log"
MODEL_FILE="$ML_HOME/sentinel_model.tflite"
TRAINING_DATA="$ML_HOME/training_data.csv"
DETECTION_INTERVAL=60
mkdir -p "$ML_HOME"
touch "$TRAINING_DATA"
log() { echo -e "[*] $1"; echo "$(date '+%F %T') - $1" >> "$LOG_FILE"; }
capture_features() {
  TCPDUMP_OUT="$ML_HOME/tcpdump_$(date '+%F_%T').log"
  timeout 10 tcpdump -n -c 100 > "$TCPDUMP_OUT" 2>/dev/null
  TOTAL_PKTS=$(wc -l < "$TCPDUMP_OUT")
  UNIQUE_IPS=$(awk '{print $3}' "$TCPDUMP_OUT" | cut -d. -f1-4 | sort -u | wc -l)
  UNIQUE_PORTS=$(awk '{print $5}' "$TCPDUMP_OUT" | cut -d. -f5 | sort -u | wc -l)
  CPU=$(top -bn1 | grep "Cpu(s)" | awk '{print 100 - $8}')
  MEM=$(free | grep Mem | awk '{print $3/$2 * 100.0}')
  echo "$TOTAL_PKTS,$UNIQUE_IPS,$UNIQUE_PORTS,$CPU,$MEM" >> "$TRAINING_DATA"
}
train_model() {
python3 << EOF2
import pandas as pd, numpy as np, tensorflow as tf
df = pd.read_csv("$TRAINING_DATA", names=["pkts","ips","ports","cpu","mem"])
X = df.values.astype(np.float32)
y = np.zeros((X.shape[0],1))
model = tf.keras.Sequential([tf.keras.layers.InputLayer(input_shape=(5,)),tf.keras.layers.Dense(16, activation='relu'),tf.keras.layers.Dense(8, activation='relu'),tf.keras.layers.Dense(1, activation='sigmoid')])
model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
model.fit(X, y, epochs=10, batch_size=4)
converter = tf.lite.TFLiteConverter.from_keras_model(model)
tflite_model = converter.convert()
with open("$MODEL_FILE", "wb") as f: f.write(tflite_model)
EOF2
}
detect_anomalies() {
python3 << EOF2
import tensorflow as tf, pandas as pd, numpy as np
interpreter = tf.lite.Interpreter(model_path="$MODEL_FILE")
interpreter.allocate_tensors()
input_details = interpreter.get_input_details()
output_details = interpreter.get_output_details()
df = pd.read_csv("$TRAINING_DATA", names=["pkts","ips","ports","cpu","mem"])
X = df.values[-1].astype(np.float32).reshape(1,5)
interpreter.set_tensor(input_details[0]['index'], X)
interpreter.invoke()
output = interpreter.get_tensor(output_details[0]['index'])[0][0]
if output > 0.5: print("ALERTA: comportamento suspeito detectado!")
EOF2
}
main() {
  log "Sentinel ML ativo"
  while true; do
    capture_features
    train_model
    detect_anomalies
    sleep $DETECTION_INTERVAL
  done
}
main
EOF
  chmod +x "$ML_HOME/sentinel_ml.sh"
}

# --- CONFIGURAR SERVIÇOS SYSTEMD ---
configure_services() {
  log "Criando serviços systemd para Sentinel Guard e ML..."
  cat << EOF > /etc/systemd/system/sentinel_guard.service
[Unit]
Description=Sentinel Guard Service
After=network.target

[Service]
ExecStart=$GUARD_HOME/sentinel_guard.sh
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

  cat << EOF > /etc/systemd/system/sentinel_ml.service
[Unit]
Description=Sentinel ML Service
After=network.target

[Service]
ExecStart=$ML_HOME/sentinel_ml.sh
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable sentinel_guard.service
  systemctl enable sentinel_ml.service
}

# --- FINALIZAÇÃO ---
finish_install() {
  log "Instalação completa SentinelOS Full Enterprise!"
  echo -e "${GREEN}Reinicie o sistema para aplicar todas as configurações e iniciar os serviços Sentinel Guard e ML automaticamente.${NC}"
}

# --- EXECUÇÃO ---
main() {
  banner
  check_root
  install_dependencies
  install_hardened_kernel
  configure_firewall
  run_hardening
  install_privacy_tools
  install_sandbox
  setup_encryption
  install_sentinel_guard
  install_sentinel_ml
  configure_services
  finish_install
}

main "$@"
