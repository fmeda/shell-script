#!/bin/bash

# ==========================================
# Linux Threat Pulse - v4 Governance Edition
# ==========================================

VERSION="4.0"
OUTPUT_DIR="./reports"
JSON_FILE="$OUTPUT_DIR/threat_pulse.json"
AUDIT_LOG="$OUTPUT_DIR/audit.log"
DATE=$(date "+%Y-%m-%d %H:%M:%S")
HOST=$(hostname)

mkdir -p "$OUTPUT_DIR"

RISK_SCORE=0
EVENT_ID=0

# ------------------------------------------
# Logging (Governance)
# ------------------------------------------
log_audit(){
    echo "[$DATE][$HOST][$1] $2" >> "$AUDIT_LOG"
}

# ------------------------------------------
# Version Compare (FIXED)
# ------------------------------------------
version_lt() {
    [ "$(printf '%s\n' "$1" "$2" | sort -V | head -n1)" != "$2" ]
}

# ------------------------------------------
# JSON INIT (SIEM READY)
# ------------------------------------------
echo "{" > "$JSON_FILE"
echo "\"host\":\"$HOST\"," >> "$JSON_FILE"
echo "\"scan_date\":\"$DATE\"," >> "$JSON_FILE"
echo "\"framework_version\":\"$VERSION\"," >> "$JSON_FILE"
echo "\"events\":[" >> "$JSON_FILE"

FIRST=true

json_event(){
    ((EVENT_ID++))

    if [ "$FIRST" = false ]; then echo "," >> "$JSON_FILE"; fi
    FIRST=false

    echo "{
      \"id\":$EVENT_ID,
      \"category\":\"$1\",
      \"severity\":\"$2\",
      \"message\":\"$3\",
      \"timestamp\":\"$DATE\"
    }" >> "$JSON_FILE"

    log_audit "$2" "$3"
}

# ------------------------------------------
# 1. Kernel Check (Contextual)
# ------------------------------------------
check_kernel(){
    KERNEL=$(uname -r)

    if [[ "$KERNEL" == 5.* ]]; then
        json_event "kernel" "high" "Kernel 5.x exposed to recent CVEs"
        ((RISK_SCORE+=20))
    fi
}

# ------------------------------------------
# 2. SUDO Check
# ------------------------------------------
check_sudo(){
    if command -v sudo &>/dev/null; then
        SUDO_V=$(sudo -V | head -n1 | awk '{print $3}')

        if version_lt "$SUDO_V" "1.9.17p1"; then
            json_event "privilege_escalation" "critical" "Outdated sudo version"
            ((RISK_SCORE+=30))
        fi
    fi
}

# ------------------------------------------
# 3. AppArmor Check (Security Control Risk)
# ------------------------------------------
check_apparmor(){
    if command -v aa-status &>/dev/null; then
        if aa-status | grep -q complain; then
            json_event "security_control" "high" "AppArmor in complain mode"
            ((RISK_SCORE+=15))
        fi
    fi
}

# ------------------------------------------
# 4. Advanced Auth Analysis (Improved)
# ------------------------------------------
check_auth(){
    LOG="/var/log/auth.log"

    if [ -f "$LOG" ]; then
        FAIL=$(grep -Ei "failed|authentication failure" "$LOG" | tail -n 50 | wc -l)
        SUDO_USE=$(grep "sudo" "$LOG" | tail -n 50 | wc -l)

        # CORRELATION (Kill Chain)
        if [ "$FAIL" -gt 5 ] && [ "$SUDO_USE" -gt 3 ]; then
            json_event "attack_chain" "critical" "Brute force + privilege escalation pattern"
            ((RISK_SCORE+=35))
        fi
    fi
}

# ------------------------------------------
# 5. Process Behavior (Red Team Resistance)
# ------------------------------------------
check_process(){
    SUSPICIOUS=$(ps aux | awk '$3 > 70 {print $0}' | wc -l)

    if [ "$SUSPICIOUS" -gt 0 ]; then
        json_event "process_behavior" "medium" "High CPU suspicious processes"
        ((RISK_SCORE+=10))
    fi
}

# ------------------------------------------
# 6. Network Exposure
# ------------------------------------------
check_network(){
    PORTS=$(ss -tuln | wc -l)

    if [ "$PORTS" -gt 50 ]; then
        json_event "network_exposure" "medium" "High number of open ports"
        ((RISK_SCORE+=10))
    fi
}

# ------------------------------------------
# 7. File Integrity (Governance Evidence)
# ------------------------------------------
check_files(){
    PERM=$(stat -c "%a" /etc/passwd)

    if [ "$PERM" != "644" ]; then
        json_event "integrity" "critical" "Critical file permission anomaly"
        ((RISK_SCORE+=25))
    fi
}

# ------------------------------------------
# 8. Correlation Engine (NEW)
# ------------------------------------------
correlation_engine(){

    if [ "$RISK_SCORE" -ge 60 ]; then
        json_event "correlation" "high" "Multiple indicators suggest compromise"
    fi
}

# ------------------------------------------
# 9. Response Engine (Controlled)
# ------------------------------------------
response_engine(){

    if [ "$RISK_SCORE" -ge 80 ]; then
        json_event "response" "action" "Response recommended: isolate host"

        # SAFE MODE (no auto-damage)
        # Example (disabled by default):
        # iptables -A INPUT -j DROP
    fi
}

# ------------------------------------------
# EXECUTION
# ------------------------------------------
check_kernel
check_sudo
check_apparmor
check_auth
check_process
check_network
check_files

correlation_engine
response_engine

# ------------------------------------------
# FINALIZE JSON
# ------------------------------------------
echo "]," >> "$JSON_FILE"
echo "\"risk_score\":$RISK_SCORE" >> "$JSON_FILE"
echo "}" >> "$JSON_FILE"

echo "Scan completed - Risk Score: $RISK_SCORE"
echo "Audit Log: $AUDIT_LOG"
echo "JSON Report: $JSON_FILE"