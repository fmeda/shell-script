#!/usr/bin/env bash
set -Eeuo pipefail

#############################################
# VERSION / GLOBAL CONFIG
#############################################

VERSION="5.0"
SSH_PORT=2222
DRY_RUN=false
VERBOSE=true

REAL_USER="${SUDO_USER:-$USER}"
USER_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"

STAMP="$(date +%F-%H%M%S)"
BACKUP_DIR="/root/hardening-backups-$STAMP"
LOG_FILE="/var/log/hardening.log"

EXPECTED_HASH="COLE_HASH_AQUI"
ALLOWED_USER="root"
ALLOWED_HOSTNAME="$(hostname)"

#############################################
# SECURE ENV
#############################################

export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
unset LD_PRELOAD
unset LD_LIBRARY_PATH
set -o noclobber

#############################################
# UI
#############################################

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()    { echo -e "${GREEN}[✔]${NC} $*"; }
info()   { echo -e "${BLUE}[➜]${NC} $*"; }
warn()   { echo -e "${YELLOW}[!]${NC} $*" >&2; }
error()  { echo -e "${RED}[✖]${NC} $*" >&2; }

exec > >(tee -i "$LOG_FILE")
exec 2>&1

#############################################
# HELP
#############################################

show_help() {
cat <<EOF
Hardening Script v$VERSION

USO:
  sudo ./hardening.sh [OPÇÕES]

OPÇÕES:
  --port <porta>     Porta SSH (default: 2222)
  --dry-run          Simulação
  --help             Ajuda

SEGURANÇA:
  - Zero Trust + TPM
  - SSH Hardened
  - Firewall (egress control)
  - Kernel Hardening
  - Audit + Integrity
EOF
exit 0
}

#############################################
# ARGUMENT PARSER
#############################################

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) SSH_PORT="$2"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    --help) show_help ;;
    *) error "Opção inválida: $1"; exit 1 ;;
  esac
done

#############################################
# EXEC WRAPPER
#############################################

run() {
  if [[ "$DRY_RUN" = true ]]; then
    echo "[DRY-RUN] $*"
  else
    eval "$@"
  fi
}

#############################################
# ZERO TRUST CHECKS
#############################################

verify_integrity() {
  info "Validando integridade..."
  [[ "$(sha256sum "$0" | awk '{print $1}')" == "$EXPECTED_HASH" ]] || {
    error "Script alterado!"
    exit 1
  }
}

verify_signature() {
  info "Validando assinatura..."
  gpg --verify "$0.sig" "$0" >/dev/null 2>&1 || {
    error "Assinatura inválida!"
    exit 1
  }
}

verify_permissions() {
  [[ "$(stat -c %U "$0")" == "root" ]] || exit 1
  [[ "$(stat -c %a "$0")" == "700" ]] || exit 1
}

verify_execution_context() {
  [[ "$(whoami)" == "$ALLOWED_USER" ]] || exit 1
  [[ "$(hostname)" == "$ALLOWED_HOSTNAME" ]] || exit 1
}

#############################################
# TPM VALIDATION
#############################################

verify_tpm_state() {
  info "Validando TPM..."
  tpm2_pcrread sha256:8 > /tmp/current_pcr
  diff /tmp/current_pcr /etc/security/pcr_baseline >/dev/null || {
    error "Sistema comprometido!"
    exit 1
  }
}

#############################################
# PRE-CHECKS
#############################################

check_root() {
  [[ "$EUID" -eq 0 ]] || { error "Execute como root"; exit 1; }
}

#############################################
# BACKUP + ROLLBACK
#############################################

rollback() {
  warn "Rollback acionado"
  cp -a "$BACKUP_DIR/sshd_config.bak" /etc/ssh/sshd_config || true
  systemctl restart ssh || true
}

trap rollback ERR

create_backup() {
  info "Criando backup..."
  run "mkdir -p $BACKUP_DIR"
  run "cp -a /etc/ssh/sshd_config $BACKUP_DIR/sshd_config.bak || true"
}

#############################################
# PACKAGE INSTALL
#############################################

install_packages() {
  info "Instalando pacotes..."
  run "apt update"
  run "apt install -y openssh-server ufw fail2ban apparmor auditd \
  unattended-upgrades apt-listchanges needrestart lynis aide rkhunter tpm2-tools"
}

#############################################
# SSH HARDENING
#############################################

configure_ssh() {
  info "Configurando SSH..."

  run "groupadd -f sshusers"
  run "usermod -aG sshusers $REAL_USER"

  run "cat > /etc/ssh/sshd_config <<EOF
Port $SSH_PORT
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AllowGroups sshusers
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowTcpForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
UseDNS no
EOF"

  run "sshd -t"
  run "systemctl restart ssh"
}

#############################################
# FIREWALL
#############################################

configure_firewall() {
  info "Configurando firewall..."

  run "ufw --force reset"
  run "ufw default deny incoming"
  run "ufw default deny outgoing"

  run "ufw allow $SSH_PORT/tcp"
  run "ufw allow out 53"
  run "ufw allow out 80"
  run "ufw allow out 443"

  run "ufw --force enable"
}

#############################################
# SYSCTL HARDENING
#############################################

configure_sysctl() {
  info "Aplicando hardening kernel..."

  run "cat > /etc/sysctl.d/99-hardening.conf <<EOF
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.randomize_va_space = 2
kernel.unprivileged_bpf_disabled = 1
kernel.kexec_load_disabled = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
kernel.unprivileged_userns_clone = 0
EOF"

  run "sysctl --system"
}

#############################################
# AUDIT + INTEGRITY
#############################################

configure_auditd() {
  info "Configurando auditd..."

  run "cat > /etc/audit/rules.d/hardening.rules <<EOF
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/ssh/sshd_config -p wa -k ssh
EOF"

  run "systemctl restart auditd"
}

configure_integrity() {
  info "Inicializando AIDE..."
  run "aideinit || true"
}

#############################################
# EXTRA HARDENING
#############################################

protect_tmp() {
  info "Protegendo /tmp..."
  run "mount -o remount,noexec,nosuid,nodev /tmp || true"
}

disable_modules() {
  info "Desabilitando módulos..."
  run "cat > /etc/modprobe.d/hardening.conf <<EOF
install cramfs /bin/false
install udf /bin/false
EOF"
}

#############################################
# MAIN
#############################################

main() {

  echo -e "${BLUE}=== HARDENING v$VERSION (ZERO TRUST + TPM) ===${NC}"

  verify_integrity
  verify_signature
  verify_permissions
  verify_execution_context
  verify_tpm_state

  check_root
  create_backup
  install_packages

  configure_ssh
  configure_firewall
  configure_sysctl
  configure_auditd
  configure_integrity

  protect_tmp
  disable_modules

  log "Hardening completo aplicado com sucesso"
}

main