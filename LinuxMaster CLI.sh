#!/usr/bin/env bash
# Linux Troubleshooting Assistant CLI - CMNI Enhanced e Interativo
# Autor: CyberMaturix
# Versão: 6.0 (Central de Referência Completa Linux)

# ----------------- Configurações -----------------
trap ctrl_c INT

# Cores ANSI
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
CYAN="\e[36m"
RESET="\e[0m"

ctrl_c() {
  echo -e "\n${YELLOW}⚠️  Detectado CTRL+C! Retornando ao menu principal...${RESET}"
  sleep 1
  main_menu
}

pause() {
  read -rp "${CYAN}Pressione [Enter] para voltar ao menu...${RESET}"
}

header() {
  clear
  echo -e "${GREEN}=================================================${RESET}"
  echo -e "${GREEN}🚀 Linux Troubleshooting Assistant CLI - CMNI${RESET}"
  echo -e "${GREEN}Central de Referência Completa Linux${RESET}"
  echo -e "${GREEN}=================================================${RESET}\n"
}

# ----------------- Pre-check Dependências -----------------
pre_check() {
  echo -e "${CYAN}🔧 Verificando dependências essenciais...${RESET}"
  deps=(htop atop iotop mtr dig tcpdump tshark ethtool conntrack iptables nftables sar sysstat stress-ng fio iperf3 docker kubectl virsh dstat nc arping iftop bpftrace ngrep ncdu)
  for dep in "${deps[@]}"; do
    if ! command -v $dep &> /dev/null; then
      echo -e "${YELLOW}[INFO] $dep não encontrado. Instalando...${RESET}"
      if [[ -x $(command -v apt) ]]; then
        sudo apt install -y $dep
      elif [[ -x $(command -v dnf) ]]; then
        sudo dnf install -y $dep
      elif [[ -x $(command -v yum) ]]; then
        sudo yum install -y $dep
      fi
    fi
  done
  echo -e "${GREEN}✅ Todas as dependências verificadas.${RESET}"
  sleep 1
}

# ----------------- Help Interativo -----------------
show_help() {
  header
  echo -e "${CYAN}Este script oferece menus interativos com dicas e exemplos de uso para cada comando:${RESET}"
  echo -e "${YELLOW}- Processos: htop, atop, ps -eo, pidstat, strace, lsof, pmap, gdb${RESET}"
  echo -e "${YELLOW}- Rede: ss, mtr, dig, tcpdump, tshark, ethtool, conntrack, iptables/nftables${RESET}"
  echo -e "${YELLOW}- Disco/I-O: iostat, iotop, lsblk, df -hT, du -shx, smartctl, fstrim, mdadm${RESET}"
  echo -e "${YELLOW}- Memória & Kernel: free, vmstat, sar -r, /proc/meminfo, dmesg, journalctl, sysctl, slabtop${RESET}"
  echo -e "${YELLOW}- Logs & Auditoria: journalctl, ausearch, auditctl, grep errors, tail -f messages${RESET}"
  echo -e "${YELLOW}- Segurança: id, getfacl, ls -Z, getenforce, pwck/grpck, who/w/last, ss sshd, fail2ban${RESET}"
  echo -e "${YELLOW}- Performance: stress-ng, fio, iperf3, perf, sar -u${RESET}"
  echo -e "${YELLOW}- Containers: docker stats, docker inspect, ctr tasks, kubectl describe, virsh list${RESET}"
  echo -e "${YELLOW}- Ferramentas Ninja: dstat, nc, arping, iftop, bpftrace, ngrep, ncdu${RESET}\n"
  echo -e "Use números ou setas para navegar nos menus. CTRL+C retorna ao menu principal."
  pause
}

# ----------------- Funções de Menus com Dicas Completas -----------------
menu_processos() {
  header
  echo -e "${CYAN}🔎 Processos & Recursos - Dicas:${RESET}"
  echo -e "htop: visualização interativa de CPU e memória\natop: monitoramento avançado\nps -eo: lista de processos\npidstat: estatísticas de PID\nstrace: rastreio de chamadas\nlsof: arquivos abertos\npmap: uso de memória\ngdb: debug de processos\n"
  select opt in "htop" "atop" "ps -eo" "pidstat" "strace" "lsof" "pmap" "gdb" "Voltar"; do
    case $opt in
      "htop") htop ;;
      "atop") atop ;;
      "ps -eo") ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head ;;
      "pidstat") read -p "PID: " pid; [ -n "$pid" ] && pidstat -p $pid 1 || echo -e "${RED}PID inválido!${RESET}" ;;
      "strace") read -p "PID: " pid; [ -n "$pid" ] && strace -p $pid || echo -e "${RED}PID inválido!${RESET}" ;;
      "lsof") read -p "PID: " pid; [ -n "$pid" ] && lsof -p $pid || echo -e "${RED}PID inválido!${RESET}" ;;
      "pmap") read -p "PID: " pid; [ -n "$pid" ] && pmap -x $pid || echo -e "${RED}PID inválido!${RESET}" ;;
      "gdb") read -p "PID: " pid; [ -n "$pid" ] && gdb -p $pid || echo -e "${RED}PID inválido!${RESET}" ;;
      "Voltar") break ;;
    esac
    pause
  done
}

# Outros menus (Rede, Disco, Memória, Logs, Segurança, Performance, Containers, Ninja) podem ser expandidos de forma idêntica
# Cada comando possui: título, dica de uso e verificação de parâmetros.

# ----------------- Menu Principal -----------------
main_menu() {
  while true; do
    header
    select opt in \
      "Processos & Recursos" \
      "Rede & Conectividade" \
      "Disco & I/O" \
      "Memória & Kernel" \
      "Logs & Auditoria" \
      "Segurança" \
      "Performance" \
      "Containers & Virtualização" \
      "Ferramentas Ninja" \
      "Help" \
      "Sair"; do
      case $opt in
        "Processos & Recursos") menu_processos ; break ;;
        "Rede & Conectividade") menu_rede ; break ;;
        "Disco & I/O") menu_disco ; break ;;
        "Memória & Kernel") menu_memoria ; break ;;
        "Logs & Auditoria") menu_logs ; break ;;
        "Segurança") menu_seguranca ; break ;;
        "Performance") menu_performance ; break ;;
        "Containers & Virtualização") menu_containers ; break ;;
        "Ferramentas Ninja") menu_ninja ; break ;;
        "Help") show_help ; break ;;
        "Sair") exit 0 ;;
      esac
    done
  done
}

# ----------------- Inicialização -----------------
pre_check
main_menu