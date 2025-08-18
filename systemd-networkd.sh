#!/bin/bash
# systemd-networkd.sh
# Script de operação de rede tática.
# Nomes e processos camuflados para evitar detecção.

set -o errexit
set -o nounset
set -o pipefail

# --- Variáveis de Configuração ---
readonly IFACE="${1:-wlan0}"
readonly DNS_SERVERS=(cloudflare quad9-dnscrypt-ip4-doh google adguard-dns opendns)
readonly TOR_UID=$(id -u debian-tor)
readonly KILL_SWITCH_CHAIN="GHOST-KILL-SWITCH"

# --- Funções Internas (Camufladas) ---

_setup_network_services() {
    echo "[*] Configurando serviços de rede..." > /dev/null
    
    # Executa dnscrypt-proxy de forma mais silenciosa
    # A configuração é passada via stdin para não criar um arquivo no disco
    (
        while true; do
            local rand_server=$(shuf -n1 -e "${DNS_SERVERS[@]}")
            printf "server_names = ['%s']\nlisten_addresses = ['127.0.0.1:53']\nrequire_dnssec = true\n" "$rand_server" | \
                dnscrypt-proxy -config /dev/stdin &>/dev/null
            sleep 10
        done
    ) & disown

    echo "nameserver 127.0.0.1" > /etc/resolv.conf
    echo "[+] Serviços de rede configurados." > /dev/null
}

_configure_firewall() {
    echo "[*] Configurando firewall..." > /dev/null

    iptables -F; iptables -t nat -F; iptables -t mangle -F
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP
    
    iptables -N $KILL_SWITCH_CHAIN
    iptables -A $KILL_SWITCH_CHAIN -j DROP

    iptables -A OUTPUT -o lo -j ACCEPT
    
    iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 53
    
    iptables -t nat -A OUTPUT -m owner --uid-owner $TOR_UID -j RETURN
    iptables -t nat -A OUTPUT -p tcp -o lo -j RETURN
    iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports 9040

    iptables -A OUTPUT -m owner --uid-owner $TOR_UID -j ACCEPT
    iptables -A OUTPUT -j $KILL_SWITCH_CHAIN

    iptables -t mangle -A POSTROUTING -o "$IFACE" -j TTL --ttl-set 64
    echo "[+] Firewall configurado." > /dev/null
}

_check_dependencies() {
    echo "[*] Verificando dependências..." > /dev/null
    local pkgs=(tor iptables macchanger dnscrypt-proxy shred)
    for pkg in "${pkgs[@]}"; do
        if ! command -v "$pkg" &>/dev/null; then
            echo "[!] Pacote '$pkg' não encontrado. Abortando silenciosamente." > /dev/null
            exit 1
        fi
    done
}

_check_tor_connectivity() {
    echo "[*] Verificando serviço Tor..." > /dev/null
    if ! systemctl is-active --quiet tor; then
        systemctl start tor
        sleep 5
    fi
    if ! curl --max-time 10 --socks5-hostname 127.0.0.1:9050 https://check.torproject.org &>/dev/null; then
        echo "[!] Falha na conectividade Tor. Abortando silenciosamente." > /dev/null
        exit 1
    fi
}

_cleanup_and_exit() {
    echo "[*] Limpando rastros e restaurando..." > /dev/null
    systemctl stop --now dnscrypt-proxy || true
    
    journalctl --flush --rotate
    journalctl --vacuum-time=1s
    shred -zu ~/.bash_history || true
    rm -rf /var/log/lastlog /var/log/wtmp /var/log/btmp || true
    rm -rf /tmp/* || true
    rm -rf ~/.cache/* || true

    iptables -F; iptables -t nat -F; iptables -t mangle -F
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT

    echo "nameserver 1.1.1.1" > /etc/resolv.conf
    echo "[+] Limpeza concluída e estado restaurado." > /dev/null
}

_panic_button() {
    echo "[!!!] MODO DE PÂNICO ACIONADO. DELETANDO E DESLIGANDO. [!!!]" > /dev/null
    _cleanup_and_exit
    ip link set dev "$IFACE" down
    sleep 3
    shutdown -h now
}

# --- Fluxo Principal ---

if [[ $EUID -ne 0 ]]; then
    exit 1
fi

case "${2:-}" in
    --start)
        _check_dependencies
        _configure_firewall
        _check_tor_connectivity
        _setup_network_services
        ;;
    --stop)
        _cleanup_and_exit
        ;;
    --panic)
        _panic_button
        ;;
    *)
        exit 1
        ;;
esac