#!/usr/bin/env bash
#
# military_harden_v4_full.sh
# MILITARY v4 FULL - single-file consolidated CLI for hardened external media
# Features: create/backup/restore/rollback/verify/status/destroy/install-deps/prepare-host/help
# See help: sudo ./military_harden_v4_full.sh help
#
set -euo pipefail
IFS=$'\n\t'

# -----------------------
# GLOBAL CONFIGURATION
# -----------------------
LOGDIR="/var/log/military_harden"
KEYSTORE_DIR="/root/military_keys"
HEADER_VERSION_DIR="/root/military_headers"
FINGERPRINT_DIR="/root/military_fprints"
RESTORE_DOCS_DIR="/root/military_restore_docs"
DEFAULT_PBKDF_LIGHT_KB=$((256 * 1024))    # 256 MiB
DEFAULT_PBKDF_KB=$((512 * 1024))          # 512 MiB (default)
PBKDF_HARD_KB=$((2 * 1024 * 1024))        # 2 GiB
PBKDF_ULTRA_KB=$((4 * 1024 * 1024))       # 4 GiB
DEFAULT_CIPHER="serpent-xts-plain64"
DEFAULT_FS="ext4"
KEEP_HEADER_VERSIONS=5
SYSTEMD_TIMER="/etc/systemd/system/military-autodestruct.timer"
SYSTEMD_SERVICE="/etc/systemd/system/military-autodestruct.service"
AUTOSCRIPT="/usr/local/bin/military_autodestruct_watch.sh"

mkdir -p "${LOGDIR}" "${KEYSTORE_DIR}" "${HEADER_VERSION_DIR}" "${FINGERPRINT_DIR}" "${RESTORE_DOCS_DIR}"
chmod 700 "${LOGDIR}" "${KEYSTORE_DIR}" "${HEADER_VERSION_DIR}" "${FINGERPRINT_DIR}" "${RESTORE_DOCS_DIR}"

# -----------------------
# UTILITY FUNCTIONS
# -----------------------
log() { echo "[$(date -Is)] $*" | tee -a "${LOGDIR}/military.log"; }
err() { echo "ERROR: $*" >&2; log "ERROR: $*"; }
confirm() {
  local prompt="${1:-Confirm}"
  if [[ "${FORCE_MODE:-false}" == "true" ]]; then return 0; fi
  read -rp "${prompt} Type 'YES' to continue: " ans
  [[ "${ans}" == "YES" ]]
}
safe_cmd() { "$@" || { err "Command failed: $*"; return 1; } }

# -----------------------
# HELP / USAGE
# -----------------------
show_help() {
  cat <<'EOF'

MILITARY v4 FULL — Usage

Commands:
  create <device> [options]      Create hardened media (DESTROYS data).
  backup <device> [options]      Create versioned header backup.
  restore <device> [options]     Restore header from detached header or backup.
  rollback <device> [to]         Rollback to previous header version (to: latest|index|timestamp).
  verify <file|device>           Verify checksums or LUKS validity.
  status <device>                Show status, mappers, backups, logs.
  destroy <device> [options]     Shred headers/backups (IRREVERSIBLE).
  install-deps                   Install recommended dependencies (apt/yum detection).
  prepare-host                   Apply optional host hardening (IOMMU, auditd rules).
  help                           Show this help.

Common Options (use after command):
  --header-out <path>            Detached header output (required for create).
  --header-backup <path>         Header backup target (for backup/restore).
  --gpg-recipient "<id|email>"   Encrypt header backup + keyfiles with GPG for escrow.
  --keyfile <path>               Keyfile location (default: ${KEYSTORE_DIR}/<device>.key)
  --cipher <cipher>              Cipher (default: ${DEFAULT_CIPHER})
  --fs <ext4|xfs>                Filesystem (default: ${DEFAULT_FS})
  --randomize <none|quick|full>  Pre-randomize device (quick=first/last, full=entire device)
  --hidden                       Create hidden (decoy + secret) volume layout
  --tpm-seal                     Attempt to seal keyfile to TPM (requires clevis/tpm2-tools)
  --autodestruct <N>             Set monitor threshold N (monitor-only by default)
  --enable-autodestruct          Enable destructive autodestruct (must be used with --autodestruct)
  --keep-headers <N>             How many header versions to keep (default: ${KEEP_HEADER_VERSIONS})
  --light                        Use light KDF (256 MiB)
  --hard                         Use hard KDF (2 GiB)
  --ultra                        Use ultra KDF (4 GiB + integrity)
  --simulate                     Dry-run mode (for restore/rollback)
  --force                        Skip interactive confirmations
  -h, --help                     Show this help

Examples:
  sudo ./military_harden_v4_full.sh create /dev/sdb --header-out /safe/headers/sdb.hdr --gpg-recipient ops@example.com --hidden --hard
  sudo ./military_harden_v4_full.sh backup /dev/sdb --header-backup /safe/backups/sdb.bak --gpg-recipient ops@example.com
  sudo ./military_harden_v4_full.sh restore /dev/sdb --header-backup /safe/backups/sdb.bak --simulate
  sudo ./military_harden_v4_full.sh rollback /dev/sdb latest --force

Security Notes:
  - Detached header MUST be stored off-device and ideally offline.
  - Use GPG to escrow backups; always keep GPG private keys secure.
  - TPM sealing provides convenience but has its own threat model.
  - Autodestruct is destructive; use monitor-only mode until tested.

EOF
}

# -----------------------
# PARSING HELPERS
# -----------------------
# parse flags for current command; leaves positional args in ARGS_REMAIN
parse_flags() {
  ARGS_REMAIN=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --header-out) HEADER_OUT="$2"; shift 2;;
      --header-backup) HEADER_BACKUP="$2"; shift 2;;
      --gpg-recipient) GPG_RECIPIENT="$2"; shift 2;;
      --keyfile) KEYFILE_PATH="$2"; shift 2;;
      --cipher) CIPHER="$2"; shift 2;;
      --fs) FS_TYPE="$2"; shift 2;;
      --randomize) DO_RANDOMIZE="$2"; shift 2;;
      --hidden) CREATE_HIDDEN=true; shift;;
      --tpm-seal) USE_TPM=true; shift;;
      --autodestruct) AUTODESTRUCT_THRESHOLD="$2"; shift 2;;
      --enable-autodestruct) ENABLE_AUTODESTRUCT=true; shift;;
      --keep-headers) KEEP_HEADER_VERSIONS="$2"; shift 2;;
      --light) PBKDF_MEMORY_KB="${DEFAULT_PBKDF_LIGHT_KB}"; shift;;
      --hard) PBKDF_MEMORY_KB="${PBKDF_HARD_KB}"; shift;;
      --ultra) PBKDF_MEMORY_KB="${PBKDF_ULTRA_KB}"; ENABLE_ULTRA=true; shift;;
      --simulate) SIMULATE=true; shift;;
      --force) FORCE_MODE=true; shift;;
      -h|--help) show_help; exit 0;;
      --) shift; break;;
      -*)
        err "Unknown option: $1"; show_help; exit 2;;
      *)
        ARGS_REMAIN+=("$1"); shift;;
    esac
  done
}

# -----------------------
# DEPENDENCY CHECK
# -----------------------
check_deps() {
  local deps=(cryptsetup parted wipefs dd sha256sum lsblk mount umount mkfs.ext4 mkfs.xfs tune2fs)
  local missing=()
  for d in "${deps[@]}"; do
    if ! command -v "${d}" >/dev/null 2>&1; then missing+=("${d}"); fi
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    err "Missing dependencies: ${missing[*]} - run 'install-deps' or install packages manually."
    return 1
  fi
  return 0
}

# -----------------------
# LOW-LEVEL HELPERS
# -----------------------
write_sha256() {
  local f="$1"
  if [[ -f "$f" ]]; then
    sha256sum "$f" > "${f}.sha256"
    chmod 600 "${f}.sha256"
    log "SHA256: ${f}.sha256"
  fi
}

header_backup_versioned() {
  local src_part="$1"
  local base_name="$2"
  local timestamp; timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  local dest="${HEADER_VERSION_DIR}/${base_name}.v${timestamp}.hdr"
  cryptsetup luksHeaderBackup --header-backup-file "${dest}" "${src_part}"
  chmod 600 "${dest}"
  write_sha256 "${dest}"
  # rotate
  ls -1t "${HEADER_VERSION_DIR}/${base_name}"*.hdr 2>/dev/null | sed -n "$((KEEP_HEADER_VERSIONS+1)),\$p" | xargs -r rm -f --
  log "Header saved: ${dest}"
  echo "${dest}"
}

safe_randomize_quick() {
  local dev="$1"
  dd if=/dev/urandom of="${dev}" bs=1M count=100 conv=fsync status=progress || true
  local size; size=$(blockdev --getsize64 "${dev}")
  if [[ -n "${size}" && "${size}" -gt $((200*1024*1024)) ]]; then
    local tail_offset=$((size - 100*1024*1024))
    dd if=/dev/urandom of="${dev}" bs=1M seek=$((tail_offset / 1048576)) conv=fsync status=progress || true
  fi
}

safe_randomize_full() {
  local dev="$1"
  dd if=/dev/urandom of="${dev}" bs=4M status=progress || true
  sync
}

# attempt TPM sealing via clevis if present
tpm_seal() {
  local keyfile="$1"
  if command -v clevis >/dev/null 2>&1; then
    # clevis luks bind would directly bind a LUKS slot — prefer manual bind of keyfile
    if clevis luks bind -d "${keyfile}" tpm2 '{}' >/dev/null 2>&1; then
      log "TPM sealed via clevis (best-effort)"
      return 0
    else
      log "Clevis present but seal failed (check TPM state)."
      return 1
    fi
  fi
  log "Clevis not installed; TPM seal skipped."
  return 2
}

# generate README restore doc
generate_restore_doc() {
  local device="$1" header_file="$2" backup_file="$3" key_outer="$4" key_inner="$5"
  local doc="${RESTORE_DOCS_DIR}/README_restore_$(basename ${device})_$(date -u +%Y%m%dT%H%M%SZ).txt"
  cat > "${doc}" <<EOF
MILITARY v4 — RESTORE GUIDE
Device: ${device}
Detached header: ${header_file}
Header backup (versioned): ${backup_file}
Keyfile outer: ${key_outer}
Keyfile inner: ${key_inner}

1) Verify checksums:
   sha256sum -c ${header_file}.sha256
   sha256sum -c ${header_file}.sha256 (and for backup/keyfiles)

2) If GPG encrypted:
   gpg --decrypt ${header_file}.gpg > header.bin
   gpg --decrypt ${key_outer}.gpg > key_outer
   gpg --decrypt ${key_inner}.gpg > key_inner

3) Restore header (if needed):
   cryptsetup luksHeaderRestore --header-backup-file header.bin /dev/sdX

4) Open outer LUKS using detached header:
   cryptsetup open --header ${header_file} /dev/sdX1 military_outer --key-file ${key_outer}

5) Open inner LUKS:
   cryptsetup open /dev/mapper/military_outer military_inner --key-file ${key_inner}

6) Mount:
   mount -o ro,nodev,nosuid,noexec /dev/mapper/military_inner /mnt/recover

7) Hidden volume:
   If present, open secret image with cryptsetup open SECRET.img military_hidden --key-file ${key_inner}

Close:
   umount /mnt/recover; cryptsetup close military_inner; cryptsetup close military_outer

EOF
  chmod 600 "${doc}"
  log "Restore doc saved: ${doc}"
}

# prechecks for header file placement (prevent same-device header)
header_off_device_check() {
  local header_file="$1"
  local target_dev="$2"
  if [[ -f "${header_file}" ]]; then
    local hdr_dev; hdr_dev=$(df --output=source "${header_file}" 2>/dev/null | tail -1 || true)
    if [[ -n "${hdr_dev}" && "${hdr_dev}" == "${target_dev}"* ]]; then
      err "Header file ${header_file} appears to be on the same device as target (${target_dev}). Aborting."
      return 1
    fi
  fi
  return 0
}

# simulation dry-run checks
simulate_restore_plan() {
  local device="$1" header_file="$2" backup_file="$3"
  log "SIMULATION: Restore plan for ${device}"
  log " - header_file: ${header_file}"
  log " - backup_file: ${backup_file}"
  if [[ -n "${header_file}" && -f "${header_file}" ]]; then
    write_sha256 "${header_file}"
    sha256sum -c --status "${header_file}.sha256" && log "Header checksum OK" || log "Header checksum FAIL (or missing)"
  else
    log "Header file missing"
  fi
  if [[ -n "${backup_file}" && -f "${backup_file}" ]]; then
    write_sha256 "${backup_file}"
    sha256sum -c --status "${backup_file}.sha256" && log "Backup checksum OK" || log "Backup checksum FAIL"
  fi
  log "SIMULATION COMPLETE"
}

# -----------------------
# COMMAND IMPLEMENTATIONS
# -----------------------

cmd_install_deps() {
  # best-effort installer for apt and yum/dnf
  if command -v apt-get >/dev/null 2>&1; then
    DEPS=(cryptsetup parted wipefs coreutils util-linux gpg sha256sum lsblk dosfstools pv)
    # tpm/clevis optional
    DEPS+=(tpm2-tools clevis clevis-luks || true)
    log "Installing packages via apt-get: ${DEPS[*]}"
    apt-get update && apt-get install -y "${DEPS[@]}" || err "apt-get install failed (check privileges)."
    return 0
  elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
    PM=$(command -v dnf || command -v yum)
    DEPS=(cryptsetup parted coreutils util-linux gpg coreutils pv)
    log "Installing packages via ${PM}: ${DEPS[*]}"
    ${PM} install -y "${DEPS[@]}" || err "${PM} install failed"
    return 0
  else
    err "No supported package manager found; install dependencies manually."
    return 1
  fi
}

cmd_prepare_host() {
  # Best-effort host hardening advisories and optional toggles
  log "Preparing host: creating dirs and optional recommendations"
  mkdir -p "${KEYSTORE_DIR}" "${HEADER_VERSION_DIR}" "${FINGERPRINT_DIR}" "${RESTORE_DOCS_DIR}" "${LOGDIR}"
  chmod 700 "${KEYSTORE_DIR}" "${HEADER_VERSION_DIR}" "${FINGERPRINT_DIR}" "${RESTORE_DOCS_DIR}" "${LOGDIR}"
  # Recommend enabling IOMMU - don't modify grub automatically; only suggest changes
  echo "== Host hardening summary ==" | tee -a "${LOGDIR}/military.log"
  echo " - Ensure IOMMU enabled for DMA protection (edit kernel cmdline: intel_iommu=on or amd_iommu=on)" | tee -a "${LOGDIR}/military.log"
  echo " - Consider enabling USB lockdown / thunderbolt secure boot on the host" | tee -a "${LOGDIR}/military.log"
  echo " - Consider adding auditd rules for cryptsetup and mount operations" | tee -a "${LOGDIR}/military.log"
  echo " - Created dirs and set permissions" | tee -a "${LOGDIR}/military.log"
  # Create host status doc
  HOSTDOC="${RESTORE_DOCS_DIR}/HOST_HARDENING_STATUS_$(hostname -s)_$(date -u +%Y%m%dT%H%M%SZ).txt"
  {
    echo "Host: $(hostname -f)"
    echo "Date: $(date -u -Is)"
    echo "IOMMU loaded modules: $(lsmod | grep -E 'iommu|intel_iommu|amd_iommu' || true)"
    echo "cryptsetup version: $(cryptsetup --version 2>/dev/null || true)"
    echo "Installed tools: $(command -v gpg || echo 'gpg:missing') $(command -v clevis || echo 'clevis:missing') $(command -v tpm2_pcrread || echo 'tpm2-tools:missing')"
  } > "${HOSTDOC}"
  chmod 600 "${HOSTDOC}"
  log "Host prepare complete. See ${HOSTDOC}"
}

cmd_backup() {
  local device="$1"
  shift
  # parse flags
  PBKDF_MEMORY_KB="${DEFAULT_PBKDF_KB}"; DO_RANDOMIZE="none"; CREATE_HIDDEN=false; USE_TPM=false; ENABLE_AUTODESCTRUCT=false; SIMULATE=false; FORCE_MODE=false
  parse_flags "$@"
  check_deps || return 1
  if [[ -z "${HEADER_BACKUP:-}" ]]; then
    HEADER_BACKUP="${HEADER_VERSION_DIR}/$(basename ${device}).hdr"
  fi
  header_backup_versioned "${device}" "$(basename ${device})"
  # Optionally encrypt backup
  if [[ -n "${GPG_RECIPIENT:-}" ]]; then
    latest=$(ls -1t "${HEADER_VERSION_DIR}/$(basename ${device})"*.hdr 2>/dev/null | head -n1 || true)
    if [[ -n "${latest}" ]]; then
      gpg --yes --batch --output "${latest}.gpg" --encrypt --recipient "${GPG_RECIPIENT}" "${latest}" && rm -f "${latest}"
      log "Encrypted backup to ${latest}.gpg"
      write_sha256 "${latest}.gpg"
    fi
  fi
  return 0
}

cmd_create() {
  local device="$1"
  shift
  # defaults
  PBKDF_MEMORY_KB="${DEFAULT_PBKDF_KB}"; DO_RANDOMIZE="none"; CREATE_HIDDEN=false; USE_TPM=false; ENABLE_AUTODESCTRUCT=false; SIMULATE=false; FORCE_MODE=false; ENABLE_ULTRA=false
  parse_flags "$@"
  check_deps || return 1

  if [[ -z "${HEADER_OUT:-}" ]]; then err "--header-out required for create"; return 2; fi
  header_off_device_check "${HEADER_OUT}" "${device}" || return 3

  if [[ "${FORCE_MODE:-false}" != "true" ]]; then
    echo "WARNING: create will DESTROY all data on ${device}"
    if ! confirm "Type YES to continue"; then err "User aborted"; return 4; fi
  fi

  # Unmount any mounted partitions
  mapfile -t mountlist < <(lsblk -ln -o NAME,MOUNTPOINT "${device}" | awk '$2!="" {print "/dev/"$1}')
  for m in "${mountlist[@]:-}"; do umount "$m" || true; done

  # Randomize if requested
  if [[ "${DO_RANDOMIZE}" == "quick" ]]; then safe_randomize_quick "${device}"; fi
  if [[ "${DO_RANDOMIZE}" == "full" ]]; then safe_randomize_full "${device}"; fi

  # Wipe signatures and partition
  wipefs -a "${device}" || true
  parted --script "${device}" mklabel gpt
  parted --script "${device}" mkpart primary 1MiB 100%
  sleep 1
  if [[ "${device}" =~ nvme ]]; then PART="${device}p1"; else PART="${device}1"; fi
  if [[ ! -b "${PART}" ]]; then PART="${device}"; fi
  log "Using ${PART} as LUKS target"

  # Prepare header file location
  mkdir -p "$(dirname "${HEADER_OUT}")"
  touch "${HEADER_OUT}"
  chmod 600 "${HEADER_OUT}"

  # Generate keyfiles
  mkdir -p "${KEYSTORE_DIR}"
  KEYFILE_PATH="${KEYFILE_PATH:-${KEYSTORE_DIR}/$(basename ${device}).key}"
  INNER_KEY="${KEYSTORE_DIR}/$(basename ${device}).inner.key"
  head -c 64 /dev/random > "${KEYFILE_PATH}"; chmod 600 "${KEYFILE_PATH}"
  head -c 64 /dev/random > "${INNER_KEY}"; chmod 600 "${INNER_KEY}"
  write_sha256 "${KEYFILE_PATH}"; write_sha256 "${INNER_KEY}"

  # Outer LUKS with detached header
  log "Formatting outer LUKS (detached header -> ${HEADER_OUT})"
  cryptsetup luksFormat --type luks2 --cipher "${DEFAULT_CIPHER}" --key-size 512 --pbkdf argon2id --pbkdf-memory "${PBKDF_MEMORY_KB}" --header "${HEADER_OUT}" "${PART}" "${KEYFILE_PATH}"
  write_sha256 "${HEADER_OUT}"
  cryptsetup open --header "${HEADER_OUT}" "${PART}" military_outer --key-file "${KEYFILE_PATH}"
  MAPPER_OUT="/dev/mapper/military_outer"
  if [[ ! -b "${MAPPER_OUT}" ]]; then err "Failed opening outer mapping"; return 10; fi

  # Inner LUKS
  log "Formatting inner LUKS inside outer"
  cryptsetup luksFormat --type luks2 --cipher "${DEFAULT_CIPHER}" --key-size 512 --pbkdf argon2id --pbkdf-memory "${PBKDF_MEMORY_KB}" "${MAPPER_OUT}" "${INNER_KEY}"
  cryptsetup open "${MAPPER_OUT}" military_inner --key-file "${INNER_KEY}"
  MAPPER_IN="/dev/mapper/military_inner"

  # Hidden or plain FS
  if [[ "${CREATE_HIDDEN:-false}" == "true" ]]; then
    TMP_MNT="/mnt/military_tmp_$(date +%s)"
    mkdir -p "${TMP_MNT}"
    mount "${MAPPER_IN}" "${TMP_MNT}"
    chmod 700 "${TMP_MNT}"
    TOTAL_BYTES=$(blockdev --getsize64 "${MAPPER_IN}")
    DECOY_BYTES=$(( TOTAL_BYTES / 20 ))
    if [[ "${DECOY_BYTES}" -gt $((2*1024*1024*1024)) ]]; then DECOY_BYTES=$((2*1024*1024*1024)); fi
    dd if=/dev/zero of="${TMP_MNT}/DECOY.img" bs=1 count=0 seek="${DECOY_BYTES}" status=none
    if [[ "${FS_TYPE}" == "ext4" ]]; then mkfs.ext4 -L "$(basename ${device})_DECOY" "${TMP_MNT}/DECOY.img"; else mkfs.xfs -L "$(basename ${device})_DECOY" "${TMP_MNT}/DECOY.img"; fi
    SECRET_BYTES=$(( TOTAL_BYTES / 4 ))
    dd if=/dev/zero of="${TMP_MNT}/SECRET.img" bs=1 count=0 seek="${SECRET_BYTES}" status=none
    cryptsetup luksFormat "${TMP_MNT}/SECRET.img" "${INNER_KEY}" --type luks2 --pbkdf argon2id --pbkdf-memory "${PBKDF_MEMORY_KB}"
    cryptsetup open "${TMP_MNT}/SECRET.img" military_hidden --key-file "${INNER_KEY}"
    if [[ -b "/dev/mapper/military_hidden" ]]; then
      if [[ "${FS_TYPE}" == "ext4" ]]; then mkfs.ext4 -L "$(basename ${device})_SECRET" "/dev/mapper/military_hidden"; else mkfs.xfs -L "$(basename ${device})_SECRET" "/dev/mapper/military_hidden"; fi
      cryptsetup close military_hidden
    fi
    umount "${TMP_MNT}" || true
    rmdir "${TMP_MNT}" || true
  else
    if [[ "${FS_TYPE}" == "ext4" ]]; then mkfs.ext4 -L "$(basename ${device})" "${MAPPER_IN}"; else mkfs.xfs -L "$(basename ${device})" "${MAPPER_IN}"; fi
  fi

  # Mount read-only
  FINAL_MNT="/mnt/$(basename ${device})"
  mkdir -p "${FINAL_MNT}"
  mount -o ro,nodev,nosuid,noexec,relatime "${MAPPER_IN}" "${FINAL_MNT}" || true
  chmod 700 "${FINAL_MNT}"

  # tune ext4
  if [[ "${FS_TYPE}" == "ext4" ]]; then tune2fs -m 0 "${MAPPER_IN}" || true; fi

  # fingerprint device
  FPRINT="${FINGERPRINT_DIR}/$(basename ${device})_$(date -u +%Y%m%dT%H%M%SZ).sha512"
  dd if="${device}" bs=4M status=progress | sha512sum > "${FPRINT}" || true
  chmod 600 "${FPRINT}"
  log "Fingerprint saved: ${FPRINT}"

  # Save a header backup versioned copy
  backup_saved=$(header_backup_versioned "${PART}" "$(basename ${device})")
  # Optionally encrypt backups and keyfiles
  if [[ -n "${GPG_RECIPIENT:-}" ]]; then
    if command -v gpg >/dev/null 2>&1; then
      gpg --yes --batch --output "${backup_saved}.gpg" --encrypt --recipient "${GPG_RECIPIENT}" "${backup_saved}" && rm -f "${backup_saved}"
      gpg --yes --batch --output "${KEYFILE_PATH}.gpg" --encrypt --recipient "${GPG_RECIPIENT}" "${KEYFILE_PATH}"
      gpg --yes --batch --output "${INNER_KEY}.gpg" --encrypt --recipient "${GPG_RECIPIENT}" "${INNER_KEY}"
      write_sha256 "${backup_saved}.gpg"
      write_sha256 "${KEYFILE_PATH}.gpg"
      write_sha256 "${INNER_KEY}.gpg"
      log "Encrypted backup and keyfiles for ${GPG_RECIPIENT}"
    else
      log "gpg not found; skipping encryption"
    fi
  fi

  # TPM seal if requested
  if [[ "${USE_TPM:-false}" == "true" ]]; then
    tpm_seal "${KEYFILE_PATH}" || log "TPM seal attempt failed or unavailable"
  fi

  # Autodestruct monitor installation
  if [[ -n "${AUTODESCTRUCT_THRESHOLD:-}" ]] && [[ "${AUTODESCTRUCT_THRESHOLD}" != "0" ]]; then
    # create autoscript (monitor-only unless enabled)
    cat > "${AUTOSCRIPT}" <<AUTOSCRIPT_EOF
#!/usr/bin/env bash
THRESHOLD=${AUTODESCTRUCT_THRESHOLD}
HEADER="${HEADER_OUT}"
BACKUP_DIR="${HEADER_VERSION_DIR}"
MAPPER="military_outer"
COUNT=\$(journalctl -n 500 --no-pager | grep -c "Failed to open \${MAPPER}")
logger "military-autodestruct: \${COUNT} failed opens for \${MAPPER}"
if [[ \${COUNT} -ge \${THRESHOLD} ]]; then
  if [[ "${ENABLE_AUTODEStruct:-false}" == "true" ]]; then
    for f in \$(ls -1 \${BACKUP_DIR}/* 2>/dev/null); do shred -u -n 3 -v "\${f}" || true; done
    if [[ -f "\${HEADER}" ]]; then shred -u -n 3 -v "\${HEADER}" || true; fi
    logger "military-autodestruct: headers shredded"
  else
    logger "military-autodestruct: monitor-only threshold reached (\${COUNT})"
  fi
fi
AUTOSCRIPT_EOF
    chmod 700 "${AUTOSCRIPT}"
    cat > "${SYSTEMD_SERVICE}" <<EOF
[Unit]
Description=Military Autodestruct Check
After=network.target

[Service]
Type=oneshot
ExecStart=${AUTOSCRIPT}
EOF
    cat > "${SYSTEMD_TIMER}" <<EOF
[Unit]
Description=Run military-autodestruct every 1m

[Timer]
OnCalendar=*-*-* *:*:00
Persistent=true
Unit=military-autodestruct.service

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now "$(basename ${SYSTEMD_TIMER})" || true
    log "Autodestruct monitor installed"
  fi

  # generate README restore doc
  generate_restore_doc "${device}" "${HEADER_OUT}" "${backup_saved}" "${KEYFILE_PATH}" "${INNER_KEY}"

  log "CREATE finished. Detached header: ${HEADER_OUT}; backup: ${backup_saved}; mounted (ro): ${FINAL_MNT}"
}

cmd_restore() {
  local device="$1"
  shift
  PBKDF_MEMORY_KB="${DEFAULT_PBKDF_KB}"; DO_RANDOMIZE="none"; CREATE_HIDDEN=false; USE_TPM=false; ENABLE_AUTODESCTRUCT=false; SIMULATE=false; FORCE_MODE=false
  parse_flags "$@"
  check_deps || return 1

  # Choose header source: HEADER_OUT (detached) preferred, else HEADER_BACKUP
  local src="${HEADER_OUT:-}"
  if [[ -z "${src}" && -n "${HEADER_BACKUP:-}" ]]; then src="${HEADER_BACKUP}"; fi
  if [[ -z "${src}" ]]; then err "No header provided for restore (--header-out or --header-backup)"; return 2; fi

  # simulate
  if [[ "${SIMULATE:-false}" == "true" ]]; then simulate_restore_plan "${device}" "${src}" "${HEADER_BACKUP:-}"; return 0; fi

  header_off_device_check "${src}" "${device}" || return 3

  # Pre-backup current header
  if cryptsetup isLuks "${device}" 2>/dev/null; then
    pre=$(header_backup_versioned "${device}" "$(basename ${device})_pre_restore")
    log "Pre-restore header saved to ${pre}"
  else
    log "No existing LUKS header or not LUKS; continuing"
  fi

  # Verify checksum
  if [[ -f "${src}.sha256" ]]; then sha256sum -c --status "${src}.sha256" || { err "Checksum mismatch for ${src}"; return 4; }; fi

  if [[ "${FORCE_MODE:-false}" != "true" ]]; then
    if ! confirm "Proceed to restore header from ${src} to ${device}?"; then err "Aborted"; return 5; fi
  fi

  cryptsetup luksHeaderRestore --header-backup-file "${src}" "${device}"
  cp -f "${src}" "${HEADER_VERSION_DIR}/restored_$(date -u +%Y%m%dT%H%M%SZ).hdr"
  write_sha256 "${HEADER_VERSION_DIR}/restored_$(date -u +%Y%m%dT%H%M%SZ).hdr"
  log "Header restored from ${src} to ${device}"
}

cmd_rollback() {
  local device="$1"
  local to="${2:-latest}"
  shift 2 || true
  parse_flags "$@"
  # list versions
  mapfile -t versions < <(ls -1t "${HEADER_VERSION_DIR}/$(basename ${device})"*.hdr 2>/dev/null || true)
  if [[ ${#versions[@]} -eq 0 ]]; then err "No header versions available"; return 1; fi
  local sel=""
  if [[ "${to}" == "latest" ]]; then sel="${versions[0]}"; fi
  if [[ -z "${sel}" && "${to}" =~ ^[0-9]+$ ]]; then sel="${versions[$to]}"; fi
  if [[ -z "${sel}" ]]; then
    # try timestamp match
    for v in "${versions[@]}"; do [[ "${v}" == *"${to}"* ]] && sel="${v}" && break; done
  fi
  if [[ -z "${sel}" ]]; then err "Could not select version '${to}'"; return 2; fi
  # verify checksum
  if [[ -f "${sel}.sha256" ]]; then sha256sum -c --status "${sel}.sha256" || { err "Checksum failed for ${sel}"; return 3; }; fi
  if [[ "${SIMULATE:-false}" == "true" ]]; then simulate_restore_plan "${device}" "${sel}" ""; return 0; fi
  if [[ "${FORCE_MODE:-false}" != "true" ]]; then
    if ! confirm "Proceed to rollback device ${device} using header ${sel}?"; then err "User aborted"; return 4; fi
  fi
  # Pre-backup current header
  if cryptsetup isLuks "${device}" 2>/dev/null; then header_backup_versioned "${device}" "$(basename ${device})_pre_rollback"; fi
  cryptsetup luksHeaderRestore --header-backup-file "${sel}" "${device}"
  cp -f "${sel}" "${HEADER_VERSION_DIR}/rollback_restored_$(date -u +%Y%m%dT%H%M%SZ).hdr"
  write_sha256 "${HEADER_VERSION_DIR}/rollback_restored_$(date -u +%Y%m%dT%H%M%SZ).hdr"
  log "Rollback applied from ${sel} to ${device}"
}

cmd_verify() {
  local target="$1"
  if [[ -z "${target}" ]]; then err "verify requires a target"; return 1; fi
  if [[ -f "${target}" && -f "${target}.sha256" ]]; then
    if sha256sum -c --status "${target}.sha256"; then echo "OK"; else echo "FAILED"; fi
  elif [[ -b "${target}" ]]; then
    if cryptsetup isLuks "${target}" 2>/dev/null; then echo "Device appears to be LUKS"; else echo "Device not LUKS"; fi
  else
    echo "Target ${target} not found"
  fi
}

cmd_status() {
  local device="$1"
  echo "=== STATUS ==="
  echo "Device: ${device}"
  lsblk -o NAME,SIZE,TYPE,MOUNTPOINT "${device}" || true
  echo "Mapped devices:"
  ls /dev/mapper || true
  echo "Header backups (recent):"
  ls -1t "${HEADER_VERSION_DIR}/$(basename ${device})"*.hdr* 2>/dev/null | head -n 10 || true
  echo "Logs (tail):"
  tail -n 50 "${LOGDIR}/military.log" || true
}

cmd_destroy() {
  local device="$1"
  shift
  parse_flags "$@"
  if [[ "${FORCE_MODE:-false}" != "true" ]]; then
    echo "WARNING: destroy will shredd headers/backups IRREVERSIBLY"
    if ! confirm "Type YES to continue"; then err "Aborted"; return 1; fi
  fi
  # shred detached header(s) and backups for this device
  if [[ -n "${HEADER_OUT:-}" && -f "${HEADER_OUT}" ]]; then shred -u -n 3 -v "${HEADER_OUT}" || true; fi
  ls -1 "${HEADER_VERSION_DIR}/$(basename ${device})"*.hdr* 2>/dev/null | xargs -r -I{} shred -u -n 3 -v {} || true
  log "Destroyed header backups for ${device}"
}

# -----------------------
# MAIN DISPATCH
# -----------------------
if [[ $# -lt 1 ]]; then show_help; exit 0; fi
CMD="$1"; shift || true

# default flags
FORCE_MODE=false
SIMULATE=false
PBKDF_MEMORY_KB="${DEFAULT_PBKDF_KB}"
ENABLE_ULTRA=false
HEADER_OUT=""
HEADER_BACKUP=""
GPG_RECIPIENT=""
KEYFILE_PATH=""
FS_TYPE="${DEFAULT_FS}"
DO_RANDOMIZE="none"
CREATE_HIDDEN=false
USE_TPM=false
AUTODESCTRUCT_THRESHOLD=0
ENABLE_AUTODEStruct=false
KEEP_HEADER_VERSIONS="${KEEP_HEADER_VERSIONS}"

case "${CMD}" in
  help|-h|--help) show_help; exit 0;;
  install-deps) cmd_install_deps; exit $?;;
  prepare-host) cmd_prepare_host; exit $?;;
  create)
    if [[ $# -lt 1 ]]; then err "create requires a <device>"; show_help; exit 2; fi
    device="$1"; shift
    parse_flags "$@"
    cmd_create "${device}"; exit $?;;
  backup)
    if [[ $# -lt 1 ]]; then err "backup requires a <device>"; show_help; exit 2; fi
    device="$1"; shift
    parse_flags "$@"
    cmd_backup "${device}" "$@"; exit $?;;
  restore)
    if [[ $# -lt 1 ]]; then err "restore requires a <device>"; show_help; exit 2; fi
    device="$1"; shift
    parse_flags "$@"
    cmd_restore "${device}" "$@"; exit $?;;
  rollback)
    if [[ $# -lt 1 ]]; then err "rollback requires a <device> [to]"; show_help; exit 2; fi
    device="$1"; toarg="${2:-latest}"; shift 2 || true
    parse_flags "$@"
    cmd_rollback "${device}" "${toarg}" "$@"; exit $?;;
  verify)
    if [[ $# -lt 1 ]]; then err "verify requires target"; show_help; exit 2; fi
    cmd_verify "$1"; exit $?;;
  status)
    if [[ $# -lt 1 ]]; then err "status requires device"; show_help; exit 2; fi
    cmd_status "$1"; exit $?;;
  destroy)
    if [[ $# -lt 1 ]]; then err "destroy requires device"; show_help; exit 2; fi
    device="$1"; shift
    parse_flags "$@"
    cmd_destroy "${device}" "$@"; exit $?;;
  *)
    err "Unknown command: ${CMD}"
    show_help
    exit 3;;
esac

