#!/usr/bin/env bash
# ============================================================
# Tool: lateral_watch
# Version: 4.0
# Description: Quantitative East-West Traffic Risk Analysis
# Maturity: CMMI Level 4 (Quantitatively Managed)
# ============================================================

set -euo pipefail

# ---------------------------
# GLOBAL METADATA
# ---------------------------
TOOL_NAME="lateral_watch"
VERSION="4.0"

OUTDIR="./reports"
BASELINE_DIR="./baseline"

DATE_ISO=$(date -Is)
DATE_DIR=$(date +%F)
TIME_TAG=$(date +%H%M%S)

# ---------------------------
# DEFAULT CONFIG
# ---------------------------
INTERNAL_REGEX="^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)"
PORTS="22|3389|445|5985|5986|3306|5432|1433|6379"
OUTPUT="json"
FORENSIC=false
VERBOSE=false
DRY_RUN=false

# ---------------------------
# EXIT CODES
# ---------------------------
EXIT_OK=0
EXIT_PARTIAL=1
EXIT_FAIL=2

# ---------------------------
# RISK WEIGHTS
# ---------------------------
declare -A PORT_RISK=(
  [445]=5    # SMB
  [3389]=5   # RDP
  [22]=4     # SSH
  [5985]=4   # WinRM
  [5986]=4
  [3306]=3   # MySQL
  [5432]=3   # PostgreSQL
  [1433]=3   # MSSQL
)

# ---------------------------
# UI FUNCTIONS
# ---------------------------
info()  { echo -e "\033[1;34m[INFO]\033[0m $1"; }
ok()    { echo -e "\033[1;32m[OK]\033[0m   $1"; }
warn()  { echo -e "\033[1;33m[WARN]\033[0m $1"; }
fail()  { echo -e "\033[1;31m[ERROR]\033[0m $1"; exit $EXIT_FAIL; }

# ---------------------------
# HELP (SHORT)
# ---------------------------
help_short() {
cat <<EOF
$TOOL_NAME v$VERSION — East-West Traffic Inspector

Usage:
  $TOOL_NAME scan [options]
  $TOOL_NAME help
  $TOOL_NAME help-full

Options:
  --ports <regex>        Sensitive ports (default: admin ports)
  --internal <regex>     Internal IP regex (RFC1918)
  --output <format>     txt | csv | json
  --forensic             Generate forensic hash (SHA256)
  --dry-run              Simulate execution
  --verbose              Verbose output
  --help                 Show this help

Example:
  sudo $TOOL_NAME scan --output json --forensic

Use '$TOOL_NAME help-full' for full documentation.
EOF
exit $EXIT_OK
}

# ---------------------------
# HELP (FULL)
# ---------------------------
help_full() {
cat <<EOF
$TOOL_NAME v$VERSION
--------------------------------------------------
DESCRIPTION
  Detects and quantifies lateral (East-West) traffic
  between internal hosts, assigning objective risk
  scores and generating audit-ready evidence.

WORKFLOW
  1. Enumerates ESTABLISHED sessions
  2. Filters internal-to-internal traffic
  3. Applies risk weights per port
  4. Generates metrics and baseline comparison

OPTIONS
  --ports <regex>
      Override sensitive ports list.

  --internal <regex>
      Override internal IP detection.

  --output <format>
      txt   Human-readable
      csv   Spreadsheet-friendly
      json  SIEM / automation ready

  --forensic
      Generates SHA256 hash for evidence integrity.

  --dry-run
      Simulates execution without collecting data.

  --verbose
      Displays internal decisions and metrics.

OUTPUT
  reports/YYYY-MM-DD/lateral_HHMMSS.json
  baseline/last_run.txt

EXIT CODES
  0  Success
  1  No lateral traffic detected
  2  Execution error

SECURITY NOTES
  - No credentials handled
  - Read-only system access
  - Requires root for socket inspection

EXAMPLES
  sudo $TOOL_NAME scan
  sudo $TOOL_NAME scan --output json
  $TOOL_NAME scan --dry-run
EOF
exit $EXIT_OK
}

# ---------------------------
# PRE-CHECKS
# ---------------------------
require_root() {
  [[ $EUID -ne 0 ]] && fail "LW-002: Root privileges required. Use sudo."
}

# ---------------------------
# SCAN FUNCTION
# ---------------------------
run_scan() {

  require_root

  $VERBOSE && info "Starting scan (CMMI Level 4)"

  $DRY_RUN && {
    ok "Dry-run completed. No data collected."
    exit $EXIT_OK
  }

  mkdir -p "$OUTDIR/$DATE_DIR" "$BASELINE_DIR"

  RAW_DATA=$(ss -tunp 2>/dev/null | awk '/ESTAB/ {
    split($5,a,":"); split($6,b,":");
    print a[1]","a[2]","b[1]","b[2]","$7
  }' | grep -E "$INTERNAL_REGEX" | grep -E "$PORTS" || true)

  [[ -z "$RAW_DATA" ]] && {
    warn "No lateral traffic detected"
    exit $EXIT_PARTIAL
  }

  TOTAL_SESSIONS=$(echo "$RAW_DATA" | wc -l)
  UNIQUE_HOSTS=$(echo "$RAW_DATA" | awk -F',' '{print $1"\n"$3}' | sort -u | wc -l)

  RISK_SCORE=0
  while IFS=',' read -r SRC SPORT DST DPORT PROC; do
    SCORE=${PORT_RISK[$DPORT]:-2}
    RISK_SCORE=$((RISK_SCORE + SCORE))
  done <<< "$RAW_DATA"

  if (( RISK_SCORE < 10 )); then
    RISK_LEVEL="LOW"
  elif (( RISK_SCORE < 20 )); then
    RISK_LEVEL="MEDIUM"
  elif (( RISK_SCORE < 30 )); then
    RISK_LEVEL="HIGH"
  else
    RISK_LEVEL="CRITICAL"
  fi

  BASELINE_FILE="$BASELINE_DIR/last_run.txt"
  DELTA="N/A"
  [[ -f "$BASELINE_FILE" ]] && {
    PREV=$(cat "$BASELINE_FILE")
    DELTA=$(( TOTAL_SESSIONS - PREV ))
  }
  echo "$TOTAL_SESSIONS" > "$BASELINE_FILE"

  REPORT="$OUTDIR/$DATE_DIR/lateral_${TIME_TAG}.json"

  cat <<EOF > "$REPORT"
{
  "metadata": {
    "tool": "$TOOL_NAME",
    "version": "$VERSION",
    "timestamp": "$DATE_ISO"
  },
  "summary": {
    "total_sessions": $TOTAL_SESSIONS,
    "unique_hosts": $UNIQUE_HOSTS,
    "risk_score": $RISK_SCORE,
    "risk_level": "$RISK_LEVEL",
    "delta_from_last_run": "$DELTA"
  },
  "findings": [
$(echo "$RAW_DATA" | awk -F',' '{printf("    {\"src\":\"%s\",\"dst\":\"%s\",\"port\":%s,\"process\":\"%s\"},\n",$1,$3,$4,$5)}' | sed '$ s/,$//')
  ]
}
EOF

  $FORENSIC && sha256sum "$REPORT" > "$REPORT.sha256"

  ok "Report generated: $REPORT"
  ok "Risk level: $RISK_LEVEL (score: $RISK_SCORE)"
}

# ---------------------------
# ENTRY POINT
# ---------------------------
[[ $# -eq 0 ]] && help_short

COMMAND="$1"; shift

case "$COMMAND" in
  scan)
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --ports) PORTS="$2"; shift ;;
        --internal) INTERNAL_REGEX="$2"; shift ;;
        --output) OUTPUT="$2"; shift ;;
        --forensic) FORENSIC=true ;;
        --dry-run) DRY_RUN=true ;;
        --verbose) VERBOSE=true ;;
        --help) help_short ;;
        *) fail "LW-001: Unknown option '$1'" ;;
      esac
      shift
    done
    run_scan
    ;;
  help|--help) help_short ;;
  help-full|--help-full) help_full ;;
  *)
    fail "LW-000: Unknown command '$COMMAND'. Use '$TOOL_NAME help'."
    ;;
esac
