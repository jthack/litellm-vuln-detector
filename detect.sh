#!/usr/bin/env bash
# litellm Supply Chain Attack Detector
# Checks for IOCs from the litellm 1.82.7/1.82.8 PyPI compromise (March 24, 2026)
# Reference: https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/
#
# Author: Joseph Thacker (rez0) - https://josephthacker.com
# Usage: ./detect.sh

set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

FOUND_ISSUES=0

banner() {
    echo -e "${BLUE}${BOLD}"
    echo "======================================================"
    echo "  litellm Supply Chain Attack Detector"
    echo "  CVE: litellm 1.82.7 / 1.82.8 (PyPI)"
    echo "  Date: March 24, 2026"
    echo "======================================================"
    echo -e "${NC}"
}

ok()   { echo -e "  ${GREEN}[CLEAN]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[WARN]${NC}  $1"; }
bad()  { echo -e "  ${RED}[FOUND]${NC} $1"; FOUND_ISSUES=$((FOUND_ISSUES + 1)); }
info() { echo -e "  ${BLUE}[INFO]${NC}  $1"; }
section() { echo -e "\n${BOLD}[$1]${NC}"; }

# --- Dependency check ---
check_ripgrep() {
    if ! command -v rg &>/dev/null; then
        echo -e "${RED}ERROR: ripgrep (rg) is not installed.${NC}"
        echo ""
        echo "Install it first:"
        echo "  macOS:   brew install ripgrep"
        echo "  Ubuntu:  sudo apt install ripgrep"
        echo "  Arch:    sudo pacman -S ripgrep"
        echo "  Cargo:   cargo install ripgrep"
        exit 1
    fi
}

# --- 1. Check installed litellm version ---
check_litellm_version() {
    section "Installed litellm version"

    local found_any=0

    # Check pip (all common variants)
    for pip_cmd in pip pip3 python3\ -m\ pip python\ -m\ pip; do
        if version=$($pip_cmd show litellm 2>/dev/null | grep -i "^Version:" | awk '{print $2}'); then
            if [[ -n "$version" ]]; then
                found_any=1
                if [[ "$version" == "1.82.7" || "$version" == "1.82.8" ]]; then
                    bad "litellm ${version} installed via ${pip_cmd} — THIS IS THE COMPROMISED VERSION"
                    bad "Run: ${pip_cmd} uninstall litellm && ${pip_cmd} install litellm>=1.82.9"
                else
                    ok "litellm ${version} (not affected) via ${pip_cmd}"
                fi
                break
            fi
        fi
    done

    # Check uv
    if command -v uv &>/dev/null; then
        if uv pip show litellm &>/dev/null 2>&1; then
            version=$(uv pip show litellm 2>/dev/null | grep -i "^Version:" | awk '{print $2}')
            if [[ -n "$version" ]]; then
                found_any=1
                if [[ "$version" == "1.82.7" || "$version" == "1.82.8" ]]; then
                    bad "litellm ${version} installed via uv — THIS IS THE COMPROMISED VERSION"
                else
                    ok "litellm ${version} (not affected) via uv"
                fi
            fi
        fi
    fi

    # Check conda
    if command -v conda &>/dev/null; then
        if conda list litellm 2>/dev/null | grep -q litellm; then
            version=$(conda list litellm 2>/dev/null | grep "^litellm" | awk '{print $2}')
            if [[ -n "$version" ]]; then
                found_any=1
                if [[ "$version" == "1.82.7" || "$version" == "1.82.8" ]]; then
                    bad "litellm ${version} installed via conda — THIS IS THE COMPROMISED VERSION"
                else
                    ok "litellm ${version} (not affected) via conda"
                fi
            fi
        fi
    fi

    if [[ "$found_any" -eq 0 ]]; then
        ok "litellm is not installed"
    fi
}

# --- 2. Check for the malicious .pth file ---
check_pth_file() {
    section "Malicious .pth file (litellm_init.pth)"

    local found=0

    # Check Python site-packages directories
    for pydir in $(python3 -c "import site; print('\n'.join(site.getsitepackages() + [site.getusersitepackages()]))" 2>/dev/null); do
        if [[ -f "${pydir}/litellm_init.pth" ]]; then
            bad "FOUND: ${pydir}/litellm_init.pth"
            found=1
        fi
    done

    # Check uv cache
    local uv_cache="${HOME}/.cache/uv"
    if [[ -d "$uv_cache" ]]; then
        while IFS= read -r match; do
            bad "FOUND in uv cache: ${match}"
            found=1
        done < <(find "$uv_cache" -name "litellm_init.pth" 2>/dev/null)
    fi

    # Search common Python/package manager locations for the .pth file
    local search_dirs=(/tmp /var/tmp "${HOME}/.local" "${HOME}/.cache" "${HOME}/.venv" "${HOME}/venv")
    # Add any virtualenvs in common project dirs
    for venv in "${HOME}"/*/venv "${HOME}"/*/".venv" "${HOME}"/git/*/venv "${HOME}"/git/*/.venv; do
        [[ -d "$venv" ]] && search_dirs+=("$venv")
    done
    for sdir in "${search_dirs[@]}"; do
        [[ -d "$sdir" ]] || continue
        while IFS= read -r match; do
            bad "FOUND: ${match}"
            found=1
        done < <(find "$sdir" -maxdepth 8 -name "litellm_init.pth" -type f 2>/dev/null || true)
    done

    if [[ "$found" -eq 0 ]]; then
        ok "litellm_init.pth not found"
    fi
}

# --- 3. Check persistence: sysmon backdoor ---
check_sysmon_persistence() {
    section "Persistence: sysmon backdoor"

    local found=0

    # Check the known paths
    for path in \
        "${HOME}/.config/sysmon/sysmon.py" \
        "${HOME}/.config/sysmon/" \
        "/root/.config/sysmon/sysmon.py" \
        "/root/.config/sysmon/"; do
        if [[ -e "$path" ]]; then
            bad "FOUND: ${path}"
            found=1
        fi
    done

    # Check systemd user service
    local svc="${HOME}/.config/systemd/user/sysmon.service"
    if [[ -f "$svc" ]]; then
        bad "FOUND systemd persistence: ${svc}"
        found=1
    fi

    # Check if sysmon.service is running
    if systemctl --user is-active sysmon.service &>/dev/null 2>&1; then
        bad "sysmon.service is ACTIVE (running right now)"
        found=1
    fi

    if [[ "$found" -eq 0 ]]; then
        ok "No sysmon backdoor or systemd persistence found"
    fi
}

# --- 4. Check for exfiltration domain in logs/history ---
check_exfil_domain() {
    section "Exfiltration domain (models.litellm.cloud)"

    local found=0
    local search_paths=()

    # Build list of files to search
    for f in \
        "${HOME}/.bash_history" \
        "${HOME}/.zsh_history" \
        "${HOME}/.local/share/fish/fish_history" \
        "${HOME}/.wget-hsts"; do
        [[ -f "$f" ]] && search_paths+=("$f")
    done

    # Search shell history and logs
    if [[ ${#search_paths[@]} -gt 0 ]]; then
        while IFS= read -r match; do
            bad "Reference to exfil domain: ${match}"
            found=1
        done < <(rg --no-ignore --hidden -l "models\.litellm\.cloud" "${search_paths[@]}" 2>/dev/null || true)
    fi

    # Check DNS cache on macOS
    if command -v log &>/dev/null && [[ "$(uname)" == "Darwin" ]]; then
        if log show --predicate 'process == "mDNSResponder"' --info --last 24h 2>/dev/null | rg -q "models\.litellm\.cloud"; then
            bad "DNS resolution for models.litellm.cloud found in macOS DNS logs (last 24h)"
            found=1
        fi
    fi

    # Check /var/log if readable
    if [[ -d /var/log ]]; then
        while IFS= read -r match; do
            bad "Found in system logs: ${match}"
            found=1
        done < <(rg --no-ignore -l "models\.litellm\.cloud" /var/log/ 2>/dev/null || true)
    fi

    if [[ "$found" -eq 0 ]]; then
        ok "No references to models.litellm.cloud found"
    fi
}

# --- 5. Check for network connections to exfil domain ---
check_network() {
    section "Active network connections to exfil infrastructure"

    local found=0

    # Resolve the domain and check active connections
    if command -v lsof &>/dev/null; then
        if lsof -i -n 2>/dev/null | rg -q "litellm"; then
            bad "Active connection referencing litellm found"
            found=1
        fi
    fi

    if command -v ss &>/dev/null; then
        if ss -tnp 2>/dev/null | rg -q "litellm"; then
            bad "Active socket referencing litellm found"
            found=1
        fi
    elif command -v netstat &>/dev/null; then
        if netstat -tn 2>/dev/null | rg -q "litellm"; then
            bad "Active connection referencing litellm found"
            found=1
        fi
    fi

    if [[ "$found" -eq 0 ]]; then
        ok "No active connections to exfil infrastructure detected"
    fi
}

# --- 6. Check running processes ---
check_processes() {
    section "Suspicious processes"

    local found=0

    # Look for sysmon.py or litellm_init processes
    if pgrep -f "sysmon\.py" &>/dev/null; then
        bad "Process running sysmon.py detected"
        ps aux | grep "sysmon\.py" | grep -v grep
        found=1
    fi

    # Look for litellm_init being executed (exclude scanners/grep searching for the string)
    while IFS= read -r proc; do
        if [[ -n "$proc" ]] && ! echo "$proc" | grep -qE "(rg|grep|find|detect\.sh)" ; then
            bad "Process referencing litellm_init detected: ${proc}"
            found=1
        fi
    done < <(ps aux 2>/dev/null | grep "litellm_init" | grep -v grep || true)

    if [[ "$found" -eq 0 ]]; then
        ok "No suspicious sysmon/litellm_init processes running"
    fi
}

# --- 7. Check Kubernetes (if kubectl available) ---
check_kubernetes() {
    section "Kubernetes cluster (node-setup-* pods)"

    if ! command -v kubectl &>/dev/null; then
        info "kubectl not found — skipping Kubernetes checks"
        return
    fi

    if ! kubectl cluster-info &>/dev/null 2>&1; then
        info "No active Kubernetes cluster — skipping"
        return
    fi

    local found=0

    # Check for node-setup-* pods in kube-system
    while IFS= read -r pod; do
        if [[ -n "$pod" ]]; then
            bad "Suspicious pod in kube-system: ${pod}"
            found=1
        fi
    done < <(kubectl get pods -n kube-system -o name 2>/dev/null | rg "node-setup" || true)

    # Check for privileged alpine pods
    while IFS= read -r pod; do
        if [[ -n "$pod" ]]; then
            warn "Privileged alpine pod in kube-system: ${pod}"
            found=1
        fi
    done < <(kubectl get pods -n kube-system -o json 2>/dev/null | \
        python3 -c "
import json,sys
data=json.load(sys.stdin)
for pod in data.get('items',[]):
    for c in pod['spec'].get('containers',[]):
        if 'alpine' in c.get('image',''):
            sc = c.get('securityContext',{})
            if sc.get('privileged'):
                print(pod['metadata']['name'])
" 2>/dev/null || true)

    if [[ "$found" -eq 0 ]]; then
        ok "No suspicious node-setup-* or privileged alpine pods in kube-system"
    fi
}

# --- 8. Check if credentials may have been exfiltrated ---
check_credential_exposure() {
    section "Credential exposure assessment"

    info "If you WERE compromised, the following may have been stolen:"

    local exposed=()
    [[ -d "${HOME}/.ssh" ]] && exposed+=("SSH keys (~/.ssh/)") || true
    [[ -d "${HOME}/.aws" ]] && exposed+=("AWS credentials (~/.aws/)") || true
    [[ -d "${HOME}/.config/gcloud" ]] && exposed+=("GCP credentials (~/.config/gcloud/)") || true
    [[ -d "${HOME}/.azure" ]] && exposed+=("Azure credentials (~/.azure/)") || true
    [[ -f "${HOME}/.kube/config" ]] && exposed+=("Kubernetes config (~/.kube/config)") || true
    [[ -f "${HOME}/.gitconfig" ]] && exposed+=("Git config (~/.gitconfig)") || true
    [[ -f "${HOME}/.bash_history" ]] && exposed+=("Bash history (~/.bash_history)") || true
    [[ -f "${HOME}/.zsh_history" ]] && exposed+=("Zsh history (~/.zsh_history)") || true

    # Check for .env files in common locations
    local env_count
    env_count=$(find "${HOME}" -maxdepth 4 -name ".env" -type f 2>/dev/null | wc -l | tr -d ' ')
    [[ "$env_count" -gt 0 ]] && exposed+=("${env_count} .env file(s) under ~/") || true

    if [[ ${#exposed[@]} -gt 0 ]]; then
        for item in "${exposed[@]}"; do
            warn "At risk: ${item}"
        done
        echo ""
        info "If compromised: rotate ALL secrets, SSH keys, API keys, and cloud credentials immediately."
    fi
}

# --- Main ---
main() {
    banner
    check_ripgrep

    echo -e "${BOLD}Running checks...${NC}"

    check_litellm_version
    check_pth_file
    check_sysmon_persistence
    check_exfil_domain
    check_network
    check_processes
    check_kubernetes
    check_credential_exposure

    echo ""
    echo "======================================================"
    if [[ "$FOUND_ISSUES" -gt 0 ]]; then
        echo -e "${RED}${BOLD}  RESULT: ${FOUND_ISSUES} indicator(s) of compromise found!${NC}"
        echo ""
        echo -e "  ${RED}Immediate actions:${NC}"
        echo "    1. Uninstall litellm: pip uninstall litellm"
        echo "    2. Remove persistence: rm -rf ~/.config/sysmon/ ~/.config/systemd/user/sysmon.service"
        echo "    3. Kill processes: pkill -f sysmon.py"
        echo "    4. Rotate ALL credentials (SSH, AWS, GCP, Azure, DB passwords, API keys)"
        echo "    5. Check Kubernetes clusters for node-setup-* pods"
        echo "    6. Audit cloud access logs for unauthorized activity"
    else
        echo -e "${GREEN}${BOLD}  RESULT: No indicators of compromise found.${NC}"
        echo ""
        echo "  If you never installed litellm 1.82.7 or 1.82.8, you are not affected."
        echo "  If you did install those versions and have since upgraded, your credentials"
        echo "  may still have been exfiltrated. Rotate secrets as a precaution."
    fi
    echo "======================================================"
    echo ""
    echo "  Reference: https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/"
    echo ""

    exit "$FOUND_ISSUES"
}

main "$@"
