#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ubuntu Hardener - Hardening Automático de Ubuntu
Autor: Fabiano (Exemplo Profissional)
Versão: 2.1.0
"""

import os
import sys
import argparse
import subprocess
import hashlib
from datetime import datetime

# 🎨 Cores para UX
class Cores:
    OK = "\033[92m"
    ERRO = "\033[91m"
    ALERTA = "\033[93m"
    INFO = "\033[94m"
    RESET = "\033[0m"

# 🌐 Idiomas (PT / EN)
IDIOMAS = {
    "pt": {
        "menu": "=== Ubuntu Hardener - Menu Principal ===",
        "opt1": "1) Hardening do Firewall",
        "opt2": "2) Hardening do SSH",
        "opt3": "3) Configuração de Logs/Auditoria",
        "opt4": "4) Criptografia",
        "opt5": "5) Executar Tudo",
        "optq": "q) Sair",
        "select": "Selecione uma opção: ",
        "exit": "[INFO] Saindo...",
        "invalid": "[ALERTA] Opção inválida.",
        "firewall": "Aplicando Hardening do Firewall (UFW)",
        "ssh": "Aplicando Hardening do SSH",
        "logs": "Configurando Logs e Auditoria",
        "crypto": "Configurando Criptografia"
    },
    "en": {
        "menu": "=== Ubuntu Hardener - Main Menu ===",
        "opt1": "1) Firewall Hardening",
        "opt2": "2) SSH Hardening",
        "opt3": "3) Logs & Auditing Setup",
        "opt4": "4) Encryption",
        "opt5": "5) Run All",
        "optq": "q) Quit",
        "select": "Choose an option: ",
        "exit": "[INFO] Exiting...",
        "invalid": "[WARNING] Invalid option.",
        "firewall": "Applying Firewall Hardening (UFW)",
        "ssh": "Applying SSH Hardening",
        "logs": "Setting up Logs and Auditing",
        "crypto": "Configuring Encryption"
    }
}

# Configurações globais
QUIET_MODE = False
LANG = "pt"

# Função utilitária para log
def log(msg, tipo="INFO", color=None):
    if QUIET_MODE:
        with open("hardener.log", "a") as f:
            f.write(f"{datetime.now()} [{tipo}] {msg}\n")
    else:
        if color:
            print(f"{color}[{tipo}]{Cores.RESET} {msg}")
        else:
            print(f"[{tipo}] {msg}")

# Função para rodar comandos de forma segura
def run_cmd(cmd, desc="Executando"):
    try:
        log(desc, "INFO", Cores.INFO)
        subprocess.run(cmd, shell=True, check=True)
        log(f"{desc} concluído.", "OK", Cores.OK)
    except subprocess.CalledProcessError:
        log(f"Falha ao executar: {cmd}", "ERRO", Cores.ERRO)

# Backup antes de alterações críticas
def backup_file(file_path):
    if os.path.exists(file_path):
        backup_path = f"{file_path}.bak_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        subprocess.run(f"sudo cp {file_path} {backup_path}", shell=True)
        log(f"Backup criado: {backup_path}", "INFO", Cores.INFO)

# Geração de hash para logs (não-repúdio)
def gerar_hash_log():
    if os.path.exists("hardener.log"):
        with open("hardener.log", "rb") as f:
            conteudo = f.read()
        sha256_hash = hashlib.sha256(conteudo).hexdigest()
        with open("hardener.log.sha256", "w") as f:
            f.write(sha256_hash)
        log(f"Hash SHA-256 do log gerado: {sha256_hash}", "INFO", Cores.INFO)

# Teste pós-hardening (exemplo: checar SSH ativo)
def teste_conectividade():
    res = subprocess.run("systemctl is-active ssh", shell=True, capture_output=True, text=True)
    if "active" in res.stdout:
        log("Teste de conectividade SSH: OK", "OK", Cores.OK)
    else:
        log("SSH falhou após hardening! Possível indisponibilidade detectada.", "ERRO", Cores.ERRO)
        log("Revertendo alterações no firewall...", "ALERTA", Cores.ALERTA)
        run_cmd("sudo ufw disable", "Rollback do Firewall")

# 🔥 Firewall (UFW)
def config_firewall():
    log(IDIOMAS[LANG]["firewall"], "INFO", Cores.INFO)
    run_cmd("sudo apt-get install -y ufw", "Instalando UFW")
    run_cmd("sudo ufw default deny incoming", "Bloqueando conexões de entrada")
    run_cmd("sudo ufw default allow outgoing", "Permitindo conexões de saída")
    run_cmd("sudo ufw allow ssh", "Permitindo conexões SSH")
    run_cmd("sudo ufw enable", "Ativando UFW")

# 🔑 SSH
def config_ssh():
    log(IDIOMAS[LANG]["ssh"], "INFO", Cores.INFO)
    ssh_config = "/etc/ssh/sshd_config"
    regras = {
        "PermitRootLogin": "no",
        "PasswordAuthentication": "no",
        "X11Forwarding": "no",
        "MaxAuthTries": "3",
        "ClientAliveInterval": "300",
        "ClientAliveCountMax": "2"
    }
    try:
        backup_file(ssh_config)
        with open(ssh_config, "r") as f:
            conteudo = f.readlines()
        novo_conteudo = []
        for linha in conteudo:
            chave = linha.split()[0] if linha.strip() else ""
            if chave in regras:
                novo_conteudo.append(f"{chave} {regras[chave]}\n")
            else:
                novo_conteudo.append(linha)
        with open(ssh_config, "w") as f:
            f.writelines(novo_conteudo)
        run_cmd("sudo systemctl restart sshd", "Reiniciando serviço SSH")
    except Exception as e:
        log(f"Erro ao aplicar SSH Hardening: {e}", "ERRO", Cores.ERRO)

# 📜 Logs
def config_logs():
    log(IDIOMAS[LANG]["logs"], "INFO", Cores.INFO)
    run_cmd("sudo apt-get install -y auditd", "Instalando auditd")
    run_cmd("sudo systemctl enable auditd", "Habilitando auditd")
    run_cmd("sudo systemctl start auditd", "Iniciando auditd")

# 🔒 Criptografia
def config_crypto():
    log(IDIOMAS[LANG]["crypto"], "INFO", Cores.INFO)
    run_cmd("sudo apt-get install -y cryptsetup", "Instalando cryptsetup")
    log("A criptografia de disco completo (LUKS) deve ser configurada no setup inicial.", "ALERTA", Cores.ALERTA)

# 📋 Menu interativo
def menu():
    while True:
        print(f"""
{Cores.INFO}{IDIOMAS[LANG]["menu"]}{Cores.RESET}
{IDIOMAS[LANG]["opt1"]}
{IDIOMAS[LANG]["opt2"]}
{IDIOMAS[LANG]["opt3"]}
{IDIOMAS[LANG]["opt4"]}
{IDIOMAS[LANG]["opt5"]}
{IDIOMAS[LANG]["optq"]}
""")
        escolha = input(IDIOMAS[LANG]["select"]).strip()
        if escolha == "1":
            config_firewall()
        elif escolha == "2":
            config_ssh()
        elif escolha == "3":
            config_logs()
        elif escolha == "4":
            config_crypto()
        elif escolha == "5":
            config_firewall()
            config_ssh()
            config_logs()
            config_crypto()
        elif escolha.lower() == "q":
            log(IDIOMAS[LANG]["exit"], "INFO", Cores.INFO)
            gerar_hash_log()
            sys.exit(0)
        else:
            log(IDIOMAS[LANG]["invalid"], "ALERTA", Cores.ALERTA)

# ⚙️ Argumentos
def main():
    global QUIET_MODE, LANG

    parser = argparse.ArgumentParser(
        description="Ubuntu Hardener - Hardening Automático de Ubuntu",
        epilog="Exemplos:\n  python3 ubuntu_hardener.py --all --lang en\n  python3 ubuntu_hardener.py --ssh --quiet",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--firewall", action="store_true", help="Hardening do Firewall")
    parser.add_argument("--ssh", action="store_true", help="Hardening do SSH")
    parser.add_argument("--logs", action="store_true", help="Configuração de Logs")
    parser.add_argument("--crypto", action="store_true", help="Configuração de Criptografia")
    parser.add_argument("--all", action="store_true", help="Executar todas as opções")
    parser.add_argument("--menu", action="store_true", help="Abrir menu interativo")
    parser.add_argument("--lang", choices=["pt", "en"], default="pt", help="Idioma da interface (pt/en)")
    parser.add_argument("--quiet", action="store_true", help="Modo silencioso (logs em hardener.log)")
    parser.add_argument("--version", action="store_true", help="Mostrar versão")

    args = parser.parse_args()

    LANG = args.lang
    QUIET_MODE = args.quiet

    if args.version:
        print("Ubuntu Hardener - versão 2.1.0")
        sys.exit(0)

    if args.menu:
        menu()

    if args.all:
        config_firewall()
        config_ssh()
        config_logs()
        config_crypto()
        teste_conectividade()
        gerar_hash_log()
        sys.exit(0)

    if args.firewall:
        config_firewall()
    if args.ssh:
        config_ssh()
    if args.logs:
        config_logs()
    if args.crypto:
        config_crypto()

    if any([args.firewall, args.ssh, args.logs, args.crypto]):
        teste_conectividade()
        gerar_hash_log()

    if not any(vars(args).values()):
        parser.print_help()

if __name__ == "__main__":
    main()
