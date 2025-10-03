#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AutoForensic SOC - Coleta Forense Avançada (Windows/Linux/Mac)
Autor: Fabiano Aparecido
Versão: 3.0.0
Descrição: Coleta forense avançada com execução assíncrona, hashing de arquivos,
modo silencioso e exportação pronta para SIEM/ dashboards.
"""

import os
import platform
import subprocess
import json
import csv
import hashlib
import asyncio
from datetime import datetime
from pathlib import Path
import logging
from argparse import ArgumentParser
from tqdm import tqdm

# -------------------- Configuração de logs --------------------
logging.basicConfig(
    filename="AutoForensic_SOC.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# -------------------- Cores CLI --------------------
class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    RESET = "\033[0m"

def info(msg, quiet=False):
    if not quiet: print(f"{Colors.GREEN}[INFO]{Colors.RESET} {msg}")
    logging.info(msg)

def warn(msg, quiet=False):
    if not quiet: print(f"{Colors.YELLOW}[ALERTA]{Colors.RESET} {msg}")
    logging.warning(msg)

def error(msg, quiet=False):
    if not quiet: print(f"{Colors.RED}[ERRO]{Colors.RESET} {msg}")
    logging.error(msg)

# -------------------- Funções auxiliares --------------------
def hash_text(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def salvar_output(tipo, dados, fmt="json", quiet=False):
    Path("output").mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{tipo}_{timestamp}.{fmt}"
    filepath = os.path.join("output", filename)
    try:
        if fmt == "json":
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump({
                    "tipo": tipo,
                    "timestamp": timestamp,
                    "hash": hash_text(str(dados)),
                    "dados": dados
                }, f, indent=4)
        elif fmt == "csv":
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                for k, v in dados.items():
                    writer.writerow([k, v])
        info(f"Dados salvos em {filepath}", quiet)
    except Exception as e:
        error(f"Falha ao salvar arquivo: {e}", quiet)
    return filepath

# -------------------- Módulos de coleta --------------------
async def coleta_usuarios(quiet=False):
    info("Coletando usuários...", quiet)
    data = {}
    try:
        if platform.system() == "Windows":
            result = subprocess.check_output("net user", shell=True, text=True)
            users = [line.strip() for line in result.splitlines() if line and "-----" not in line]
            data["usuarios"] = users
        else:
            with open("/etc/passwd") as f:
                users = [line.split(":")[0] for line in f.readlines()]
            data["usuarios"] = users
    except Exception as e:
        error(f"Erro ao coletar usuários: {e}", quiet)
    salvar_output("usuarios", data, quiet=quiet)

async def coleta_logs(quiet=False):
    info("Coletando logs críticos...", quiet)
    data = {}
    try:
        if platform.system() == "Windows":
            result = subprocess.check_output("wevtutil qe System /f:text /c:50", shell=True, text=True)
            data["logs_sistema"] = result.splitlines()
        else:
            log_files = ["/var/log/syslog", "/var/log/auth.log"]
            logs = {}
            for lf in log_files:
                if os.path.exists(lf):
                    with open(lf) as f:
                        logs[lf] = f.readlines()[-50:]
            data["logs"] = logs
    except Exception as e:
        error(f"Erro ao coletar logs: {e}", quiet)
    salvar_output("logs", data, quiet=quiet)

async def coleta_conexoes(quiet=False):
    info("Coletando conexões de rede...", quiet)
    data = {}
    try:
        if platform.system() == "Windows":
            result = subprocess.check_output("netstat -an", shell=True, text=True)
        else:
            result = subprocess.check_output(["netstat", "-tunlp"], text=True)
        data["conexoes"] = result.splitlines()
    except Exception as e:
        error(f"Erro ao coletar conexões: {e}", quiet)
    salvar_output("conexoes", data, quiet=quiet)

# -------------------- Execução assíncrona --------------------
async def executar_modulos(modulos, quiet=False):
    tasks = []
    if "usuarios" in modulos: tasks.append(coleta_usuarios(quiet))
    if "logs" in modulos: tasks.append(coleta_logs(quiet))
    if "conexoes" in modulos: tasks.append(coleta_conexoes(quiet))
    if tasks:
        for f in tqdm(asyncio.as_completed(tasks), desc="Coleta em andamento", ncols=70):
            await f

# -------------------- CLI --------------------
def main():
    parser = ArgumentParser(description="AutoForensic SOC - Coleta Forense Avançada")
    parser.add_argument("--usuarios", action="store_true", help="Coleta lista de usuários")
    parser.add_argument("--logs", action="store_true", help="Coleta logs críticos")
    parser.add_argument("--conexoes", action="store_true", help="Coleta conexões de rede")
    parser.add_argument("--all", action="store_true", help="Coleta todas as informações")
    parser.add_argument("--quiet", action="store_true", help="Modo silencioso/automatizado")
    parser.add_argument("--version", action="version", version="AutoForensic SOC v3.0.0")
    args = parser.parse_args()

    modulos = []
    if args.all or not any(vars(args).values()):  # padrão para menu
        modulos = ["usuarios","logs","conexoes"]
    else:
        if args.usuarios: modulos.append("usuarios")
        if args.logs: modulos.append("logs")
        if args.conexoes: modulos.append("conexoes")

    asyncio.run(executar_modulos(modulos, quiet=args.quiet))
    if not args.quiet:
        info("Coleta concluída com sucesso!", quiet=False)

if __name__ == "__main__":
    main()
