#!/bin/bash

# Nome do dispositivo e data
DEVICE_NAME=$(adb shell getprop ro.product.model | tr -d '\r')
DATE=$(date +"%Y%m%d")
LOG_DIR="/mnt/forensics/logs"
IMAGE_DIR="/mnt/forensics/images"

# Criando diretórios
mkdir -p "$LOG_DIR" "$IMAGE_DIR"

# Log de início
echo "[INFO] Início da aquisição forense no dispositivo: $DEVICE_NAME" | tee -a "$LOG_DIR/pericia_$DEVICE_NAME_$DATE.log"

# Desativando conexões de rede
echo "[INFO] Desativando conexões de rede..." | tee -a "$LOG_DIR/pericia_$DEVICE_NAME_$DATE.log"
adb shell su -c 'svc wifi disable && svc data disable'

echo "[INFO] Coletando informações do sistema..." | tee -a "$LOG_DIR/pericia_$DEVICE_NAME_$DATE.log"
adb shell getprop > "$LOG_DIR/sysinfo_$DEVICE_NAME_$DATE.txt"

echo "[INFO] Coletando evidências voláteis..." | tee -a "$LOG_DIR/pericia_$DEVICE_NAME_$DATE.log"
adb shell su -c 'ps aux' > "$LOG_DIR/processos_$DEVICE_NAME_$DATE.txt"
adb shell su -c 'netstat -tulnp' > "$LOG_DIR/conexoes_$DEVICE_NAME_$DATE.txt"
adb shell su -c 'logcat -d' > "$LOG_DIR/logcat_$DEVICE_NAME_$DATE.txt"

# Criando imagem forense
echo "[INFO] Criando imagem forense do dispositivo..." | tee -a "$LOG_DIR/pericia_$DEVICE_NAME_$DATE.log"
adb shell su -c 'dd if=/dev/block/mmcblk0 of=/sdcard/forensics/image_android_$DATE.dd bs=4M'
adb pull /sdcard/forensics/image_android_$DATE.dd "$IMAGE_DIR/"

# Calculando hash
echo "[INFO] Calculando hash da imagem..." | tee -a "$LOG_DIR/pericia_$DEVICE_NAME_$DATE.log"
sha256sum "$IMAGE_DIR/image_android_$DATE.dd" | tee -a "$LOG_DIR/pericia_$DEVICE_NAME_$DATE.log"

echo "[INFO] Perícia concluída com sucesso." | tee -a "$LOG_DIR/pericia_$DEVICE_NAME_$DATE.log"
