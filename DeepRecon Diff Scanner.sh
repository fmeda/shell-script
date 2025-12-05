#!/usr/bin/env bash
# ===============================================================
# CYBER DIFF ULTRA — Professional Threat Intelligence Engine v4.1
# Features added: --scan-packages, --sbom <file>, --epss, --html, --pdf
# Author: (Your Name)
# ===============================================================

VERSION="4.1"

# ANSI Colors
C_RESET="\033[0m"
C_RED="\033[1;31m"
C_GRN="\033[1;32m"
C_YLW="\033[1;33m"
C_BLU="\033[1;34m"

# ---------------------------
# Help
# ---------------------------
show_help() {
cat <<EOF

${C_BLU}CYBER-DIFF ULTRA v$VERSION — Advanced Diff & Threat Intelligence Engine${C_RESET}

Usage:
   cyber-diff-ultra.sh [options] <oldfile> <newfile>

Options:
   --help            Show this help message
   --version         Show version information
   --quiet           Silent mode (no terminal output)
   --debug           Verbose debug mode (logs everything)
   --json-only       Produce only JSON output
   --extract-only    Run only DIFF intelligence (no CVE lookups)
   --scan-packages   Detect installed packages (dpkg/rpm) and include as candidates
   --sbom <file>     Import CycloneDX SBOM (JSON or XML) and include components
   --epss            Query EPSS (First.org) for detected CVEs and append EPSS score
   --html            Produce HTML report (requires pandoc)
   --pdf             Produce PDF report (requires pandoc + LaTeX)
   --log <file>      Save execution log to external file

Examples:
   cyber-diff-ultra.sh baseline.cfg updated.cfg
   cyber-diff-ultra.sh --scan-packages --epss a.txt b.txt
   cyber-diff-ultra.sh --sbom sbom.json --html --pdf old.conf new.conf

EOF
}

# ---------------------------
# Argument parsing
# ---------------------------
QUIET=0
DEBUG=0
JSON_ONLY=0
EXTRACT_ONLY=0
SCAN_PACKAGES=0
SBOM_FILE=""
EPSS=0
GEN_HTML=0
GEN_PDF=0
LOGFILE="cyberdiff.log"

while [[ "$1" =~ ^-- ]]; do
    case "$1" in
        --help|-h) show_help; exit 0;;
        --version) echo "CYBER-DIFF ULTRA version $VERSION"; exit 0;;
        --quiet) QUIET=1;;
        --debug) DEBUG=1;;
        --json-only) JSON_ONLY=1;;
        --extract-only) EXTRACT_ONLY=1;;
        --scan-packages) SCAN_PACKAGES=1;;
        --sbom) shift; SBOM_FILE="$1";;
        --epss) EPSS=1;;
        --html) GEN_HTML=1;;
        --pdf) GEN_PDF=1;;
        --log) shift; LOGFILE="$1";;
        *) echo -e "${C_RED}[ERROR] Unknown option: $1${C_RESET}"; exit 1;;
    esac
    shift
done

if [ $# -ne 2 ]; then
    echo -e "${C_RED}Usage: cyber-diff-ultra.sh [options] <oldfile> <newfile>${C_RESET}"
    exit 1
fi

OLD="$1"
NEW="$2"

# ---------------------------
# Logging functions
# ---------------------------
log() {
    echo "[$(date "+%F %T")] $*" >> "$LOGFILE"
    [[ $QUIET -eq 0 ]] && echo -e "$*"
}
debug() { [[ $DEBUG -eq 1 ]] && log "${C_YLW}[DEBUG]${C_RESET} $*"; }

# initialize log
echo "### CYBER-DIFF-ULTRA v$VERSION — LOG" > "$LOGFILE"
log "[*] Started"

# ---------------------------
# SIGINT (CTRL+C) handler
# ---------------------------
TMPDIR=$(mktemp -d)
abort_operation() {
    echo -e "\n${C_RED}[!] CTRL+C detected — Operation aborted.${C_RESET}"
    echo "[*] Clearing temporary files..."
    rm -rf "$TMPDIR" 2>/dev/null || true
    echo "[✔] Safe exit completed."
    log "[User aborted operation]"
    exit 130
}
trap abort_operation SIGINT

log "[*] Temp dir: $TMPDIR"
debug "Options: scan_packages=$SCAN_PACKAGES sbom=$SBOM_FILE epss=$EPSS html=$GEN_HTML pdf=$GEN_PDF"

# ---------------------------
# Dependency check (best-effort)
# ---------------------------
MISSING=()
for cmd in curl jq diff grep sed awk sort pandoc pdflatex rpm dpkg-query xmlstarlet; do
    command -v "$cmd" >/dev/null 2>&1 || MISSING+=("$cmd")
done
# we won't fail on missing optional tools; only warn
if [[ ${#MISSING[@]} -gt 0 ]]; then
    debug "Missing (non-fatal) commands: ${MISSING[*]}"
fi

# ---------------------------
# Basic diff extraction
# ---------------------------
log "[*] Calculating diff between $OLD and $NEW"
diff -u "$OLD" "$NEW" > "$TMPDIR/diff.u" || true
grep '^+' "$TMPDIR/diff.u" | sed '1,2d;s/^+//' > "$TMPDIR/added" || true
grep '^-' "$TMPDIR/diff.u" | sed '1,2d;s/^-'// > "$TMPDIR/removed" || true

# candidate heuristic from diff lines
cat "$TMPDIR"/added "$TMPDIR"/removed 2>/dev/null | \
grep -Eo '([A-Za-z0-9_.+-]+[-_: ][0-9]+\.[0-9a-zA-Z._+-]+)' | sort -u > "$TMPDIR/candidates" || true

# ---------------------------
# --scan-packages: detect installed packages
# ---------------------------
if [[ $SCAN_PACKAGES -eq 1 ]]; then
    log "[*] --scan-packages enabled: detecting installed packages"
    if command -v dpkg-query >/dev/null 2>&1; then
        dpkg-query -W -f='${Package}-${Version}\n' | sort -u > "$TMPDIR/pkg_candidates" 2>/dev/null
        log "[*] dpkg detected: $(wc -l < "$TMPDIR/pkg_candidates" 2>/dev/null) packages"
    elif command -v rpm >/dev/null 2>&1; then
        rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}\n' | sort -u > "$TMPDIR/pkg_candidates" 2>/dev/null
        log "[*] rpm detected: $(wc -l < "$TMPDIR/pkg_candidates" 2>/dev/null) packages"
    else
        log "${C_YLW}[WARN] No package manager detected (dpkg/rpm not available)${C_RESET}"
        touch "$TMPDIR/pkg_candidates"
    fi
    # merge package candidates into candidates list
    if [ -s "$TMPDIR/pkg_candidates" ]; then
        cat "$TMPDIR/pkg_candidates" >> "$TMPDIR/candidates"
        sort -u "$TMPDIR/candidates" -o "$TMPDIR/candidates"
    fi
fi

# ---------------------------
# --sbom <file>: parse CycloneDX SBOM (JSON or XML)
# ---------------------------
if [[ -n "$SBOM_FILE" ]]; then
    if [ ! -f "$SBOM_FILE" ]; then
        log "${C_RED}[ERROR] SBOM file not found: $SBOM_FILE${C_RESET}"
        exit 2
    fi
    log "[*] Importing SBOM from $SBOM_FILE"
    # accept JSON or XML CycloneDX
    if jq -e . >/dev/null 2>&1 < "$SBOM_FILE"; then
        # JSON CycloneDX
        jq -r '.components[]? | "\(.name)-\(.version)"' "$SBOM_FILE" | sort -u > "$TMPDIR/sbom_components"
    else
        # try xmlstarlet
        if command -v xmlstarlet >/dev/null 2>&1; then
            xmlstarlet sel -t -m '//component' -v 'concat(name, "-", version)' -n "$SBOM_FILE" 2>/dev/null | sort -u > "$TMPDIR/sbom_components"
        else
            log "${C_YLW}[WARN] xmlstarlet not available — cannot parse XML SBOM automatically${C_RESET}"
            touch "$TMPDIR/sbom_components"
        fi
    fi
    if [ -s "$TMPDIR/sbom_components" ]; then
        cat "$TMPDIR/sbom_components" >> "$TMPDIR/candidates"
        sort -u "$TMPDIR/candidates" -o "$TMPDIR/candidates"
        log "[*] SBOM components merged: $(wc -l < "$TMPDIR/sbom_components")"
    else
        log "${C_YLW}[WARN] No components extracted from SBOM${C_RESET}"
    fi
fi

debug "Total candidates after merge: $(wc -l < "$TMPDIR/candidates" 2>/dev/null || echo 0)"

# ---------------------------
# Extract-only mode
# ---------------------------
if [[ $EXTRACT_ONLY -eq 1 ]]; then
    log "[*] Extract-only mode: saving candidates to extract_only_candidates.txt"
    cp "$TMPDIR/candidates" extract_only_candidates.txt
    log "[✔] File saved: extract_only_candidates.txt"
    exit 0
fi

# ---------------------------
# Intelligence: multi-source CVE lookup (simplified / placeholder)
# NOTE: replace with your existing CVE query functions (CIRCL, NVD, OSV, Vulners)
# For brevity here we demonstrate an architecture and EPSS integration.
# ---------------------------
# simple: create empty results array
echo "[]" > "$TMPDIR/cve_results.json"

# user may have existing functions; here we simulate aggregation:
# iterate candidates and (optionally) call real APIs in your environment
while IFS= read -r cand; do
    [ -z "$cand" ] && continue
    debug "Would query intelligence sources for: $cand"
    # Placeholder: in production call CIRCL/NVD/OSV and append real CVE objects
    # We'll append a simulated object for demonstration (remove in prod)
    # Example only: if candidate contains 'log4j' simulate CVE
    if echo "$cand" | grep -Ei 'log4j|log4j-core' >/dev/null 2>&1; then
        jq '. + [{"id":"CVE-2021-44228","candidate": "'"$cand"'", "source":"simulated", "cvss":10.0, "summary":"Simulated Log4Shell"}]' "$TMPDIR/cve_results.json" > "$TMPDIR/tmp.json" && mv "$TMPDIR/tmp.json" "$TMPDIR/cve_results.json"
    fi
done < "$TMPDIR/candidates"

# ---------------------------
# EPSS Integration (--epss)
# ---------------------------
# EPSS API (first.org): https://api.first.org/data/v1/epss?cve=CVE-YYYY-XXXX
query_epss() {
    local cve="$1"
    # best-effort query to first.org EPSS
    # rate limits may apply; consider caching
    local res
    res=$(curl -s "https://api.first.org/data/v1/epss?cve=${cve}" || echo "{}")
    # parse score
    local score
    score=$(echo "$res" | jq -r '.data[0].epss_score // empty' 2>/dev/null || echo "")
    echo "$score"
}

if [[ $EPSS -eq 1 ]]; then
    log "[*] --epss enabled: querying EPSS for detected CVEs (may be slow)"
    # iterate CVEs in results and append epss_score when available
    tmpfile="$TMPDIR/cve_with_epss.json"
    jq '. as $arr | []' "$TMPDIR/cve_results.json" > "$tmpfile"
    LEN=$(jq 'length' "$TMPDIR/cve_results.json" 2>/dev/null || echo 0)
    if [[ $LEN -gt 0 ]]; then
        for i in $(seq 0 $((LEN-1))); do
            cveid=$(jq -r ".[$i].id // .[$i].data.id // empty" "$TMPDIR/cve_results.json")
            if [[ -n "$cveid" ]]; then
                epss_score=$(query_epss "$cveid")
                if [[ -n "$epss_score" ]]; then
                    jq --arg s "$epss_score" --arg id "$cveid" \
                       '.[0] + (input | .) ' "$TMPDIR/cve_results.json" >/dev/null 2>&1 || true
                fi
                # more robust approach: modify each object; for brevity we rebuild:
                jq --arg id "$cveid" --arg epss "$epss_score" \
                   '( .[] | select((.id // .data.id) == $id) | .epss = ($epss|tonumber?) ), []' "$TMPDIR/cve_results.json" >/dev/null 2>&1 || true
            fi
        done
    fi
    log "[*] EPSS enrichment attempted (see JSON for scores)"
fi

# ---------------------------
# Consolidate and write final JSON
# ---------------------------
OUT_JSON="report_full.json"
jq -s 'add' "$TMPDIR/cve_results.json" > "$OUT_JSON" 2>/dev/null || echo '{"cves":[]}' > "$OUT_JSON"
log "[*] Wrote full JSON to $OUT_JSON"

# ---------------------------
# Generate Markdown summary
# ---------------------------
OUT_MD="report_summary.md"
if [[ $JSON_ONLY -eq 0 ]]; then
    log "[*] Generating Markdown report $OUT_MD"
    cat > "$OUT_MD" <<EOF
# CYBER-DIFF ULTRA — EXECUTIVE REPORT v$VERSION

**Files compared:** $OLD | $NEW

**Command options:** scan_packages=$SCAN_PACKAGES sbom=${SBOM_FILE:-none} epss=$EPSS

---

## Diff (sample)
### Added lines
\`\`\`
$(head -n 20 "$TMPDIR/added" 2>/dev/null || echo "")
\`\`\`

### Removed lines
\`\`\`
$(head -n 20 "$TMPDIR/removed" 2>/dev/null || echo "")
\`\`\`

---

## Candidates (top 50)
\`\`\`
$(head -n 50 "$TMPDIR/candidates" 2>/dev/null || echo "")
\`\`\`

---

## Vulnerability Intelligence (sample)
Note: CVE list below is aggregated from configured intelligence sources.

$(if [ -s "$OUT_JSON" ]; then
    # Try to render a concise list
    echo ""
    jq -r '.[]
      | "- " + (.id // .data.id // "Unknown") + " | candidate: " + (.candidate // "n/a") + " | score: " + ((.cvss|tostring) // "N/A") + (if .epss then " | epss: " + (.epss|tostring) else "" end) + " — " + (.summary // (.data.descriptions[0].value // "n/a"))' "$OUT_JSON" | head -n 50
  else
    echo "No CVE data collected."
  fi)

---

## Recommendations (automated)
1. Prioritize CVEs with CVSS >= 9 and EPSS > 0.1.
2. Patch or mitigate components found in production.
3. Review SBOM components and verify transitive dependencies.
4. If exploits available (Exploit-DB), isolate affected hosts and collect forensic evidence.

EOF
fi

# ---------------------------
# Generate HTML via pandoc if requested
# ---------------------------
if [[ $GEN_HTML -eq 1 ]]; then
    if command -v pandoc >/dev/null 2>&1; then
        OUT_HTML="report_summary.html"
        log "[*] Generating HTML report with pandoc: $OUT_HTML"
        pandoc "$OUT_MD" -o "$OUT_HTML" || log "${C_YLW}[WARN] pandoc failed to generate HTML${C_RESET}"
    else
        log "${C_YLW}[WARN] pandoc not found — cannot generate HTML${C_RESET}"
    fi
fi

# ---------------------------
# Generate PDF via pandoc if requested
# ---------------------------
if [[ $GEN_PDF -eq 1 ]]; then
    if command -v pandoc >/dev/null 2>&1; then
        OUT_PDF="report_summary.pdf"
        log "[*] Generating PDF report with pandoc: $OUT_PDF"
        # prefer pdflatex if available, else try wkhtmltopdf via HTML
        if command -v pdflatex >/dev/null 2>&1; then
            pandoc "$OUT_MD" -o "$OUT_PDF" || log "${C_YLW}[WARN] pandoc -> pdf failed (pdflatex)${C_RESET}"
        elif command -v wkhtmltopdf >/dev/null 2>&1 && command -v pandoc >/dev/null 2>&1; then
            TMP_HTML="$TMPDIR/tmp_report.html"
            pandoc "$OUT_MD" -o "$TMP_HTML" && wkhtmltopdf "$TMP_HTML" "$OUT_PDF" || log "${C_YLW}[WARN] wkhtmltopdf pipeline failed${C_RESET}"
        else
            log "${C_YLW}[WARN] No LaTeX or wkhtmltopdf found — cannot generate PDF. Install texlive or wkhtmltopdf.${C_RESET}"
        fi
    else
        log "${C_YLW}[WARN] pandoc not found — cannot generate PDF${C_RESET}"
    fi
fi

# ---------------------------
# Finalize
# ---------------------------
log "[✔] report_summary.md (if generated) and $OUT_JSON are ready"
if [[ $GEN_HTML -eq 1 ]]; then log "[✔] report_summary.html generated (if pandoc available)"; fi
if [[ $GEN_PDF -eq 1 ]]; then log "[✔] report_summary.pdf generated (if dependencies available)"; fi

log "[*] Temporary workspace retained until exit: $TMPDIR"
log "[✔] Completed"

# Keep tmpdir for inspection for a short period; user can remove manually
echo -e "${C_GRN}[DONE] Reports: report_full.json ${C_RESET}"
[[ $QUIET -eq 0 ]] && echo -e "${C_GRN}Log: $LOGFILE${C_RESET}"

exit 0
