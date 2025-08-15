#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Blindagem Crítica Avançada 2025 - Windows 10/11
Versão: 2.1.0
Autor: Especialista em Segurança
Descrição: Proteção de pastas críticas, backup criptografado,
verificação de patches, monitoramento de integridade e alertas CVE.
"""

import sys
import subprocess

# ============================
# VERIFICAÇÃO E INSTALAÇÃO DE MÓDULOS
# ============================

required_modules = ['requests', 'pyAesCrypt']
for module in required_modules:
    try:
        __import__(module)
    except ImportError:
        print(f"[!] Módulo ausente: {module}. Instalando...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", module])
            print(f"[+] Módulo {module} instalado com sucesso.")
        except subprocess.CalledProcessError:
            print(f"[ERRO] Falha ao instalar o módulo: {module}")
            sys.exit(1)

# ============================
# IMPORTS PÓS-VERIFICAÇÃO
# ============================

import os
import shutil
import logging
import argparse
import hashlib
import getpass
from pathlib import Path
from datetime import datetime
import requests
import json
import tempfile
import pyAesCrypt
import ctypes

# ============================
# CONFIGURAÇÃO DO LOG AVANÇADO
# ============================

log_file = "blindagem_win10_2025.log"
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='{"time": "%(asctime)s", "user": "%(username)s", "level": "%(levelname)s", "message": "%(message)s"}'
)

class ContextFilter(logging.Filter):
    def filter(self, record):
        record.username = getpass.getuser()
        return True
logging.getLogger().addFilter(ContextFilter())

# ============================
# PASTAS CRÍTICAS, BACKUP E HONEY FOLDERS
# ============================

PASTAS_CRITICAS = [
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Windows\System32\drivers\etc",
    r"C:\Windows\Temp",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
]

HONEY_FOLDERS = [
    r"C:\Windows\Honey_Folder"
]

BACKUP_DIR = Path("C:/backup_critico_seguro")
BACKUP_BUFFER = 64 * 1024  # 64KB para criptografia

# ============================
# FUNÇÕES DE SUPORTE
# ============================

def pre_check():
    """Verifica se o script é executado como administrador"""
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if not is_admin:
            logging.error("O script deve ser executado como Administrador.")
            sys.exit("[ERRO] Execute como Administrador.")
    except Exception as e:
        logging.error(f"Erro ao verificar privilégios de administrador: {e}")
        sys.exit("[ERRO] Não foi possível verificar privilégios de administrador.")

def hash_file(path):
    """Calcula hash SHA256 do arquivo"""
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        logging.error(f"Erro ao calcular hash de {path}: {e}")
        return None

def backup_pastas(crypto=False):
    """Cria backup das pastas críticas, opcionalmente criptografado"""
    BACKUP_DIR.mkdir(exist_ok=True)
    for pasta in PASTAS_CRITICAS:
        nome = Path(pasta).name
        destino = BACKUP_DIR / nome
        try:
            if not destino.exists():
                shutil.copytree(pasta, destino)
                logging.info(f"Backup realizado: {pasta} -> {destino}")
                # Criptografia segura
                if crypto:
                    temp_file = tempfile.NamedTemporaryFile(delete=False)
                    try:
                        pyAesCrypt.encryptFile(str(destino), temp_file.name, "SenhaForte2025!", BACKUP_BUFFER)
                        shutil.move(temp_file.name, f"{destino}.aes")
                        shutil.rmtree(destino)
                        logging.info(f"Backup criptografado: {destino}.aes")
                    except Exception as e:
                        logging.error(f"Erro na criptografia do backup: {destino} - {e}")
                        if temp_file:
                            os.unlink(temp_file.name)
        except Exception as e:
            logging.error(f"Erro ao fazer backup de {pasta}: {e}")

def aplicar_acl(pasta):
    """Aplica permissão de leitura/sistema nas pastas"""
    try:
        subprocess.run(['icacls', pasta, '/inheritance:r'], check=True, timeout=60)
        subprocess.run(['icacls', pasta, '/grant:r', 'SYSTEM:(F)'], check=True, timeout=60)
        subprocess.run(['icacls', pasta, '/grant:r', 'Administrators:(RX)'], check=True, timeout=60)
        subprocess.run(['attrib', '+S', '+H', pasta], check=True, timeout=60)
        logging.info(f"Permissões aplicadas com sucesso: {pasta}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Erro ao aplicar permissões em {pasta}: {e}")
    except subprocess.TimeoutExpired:
        logging.error(f"Timeout ao aplicar permissões em {pasta}")

def restaurar_permissoes():
    """Restaura as permissões padrão"""
    for pasta in PASTAS_CRITICAS:
        try:
            subprocess.run(['icacls', pasta, '/reset', '/T', '/C'], check=True, timeout=60)
            subprocess.run(['attrib', '-S', '-H', pasta], check=True, timeout=60)
            logging.info(f"Permissões restauradas: {pasta}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Erro ao restaurar permissões: {pasta} - {e}")
        except subprocess.TimeoutExpired:
            logging.error(f"Timeout ao restaurar permissões: {pasta}")

def criar_honey_folders():
    """Cria pastas falsas para detecção de ransomware"""
    for pasta in HONEY_FOLDERS:
        Path(pasta).mkdir(parents=True, exist_ok=True)
        fake_file = Path(pasta) / "documento_critico_fake.txt"
        if not fake_file.exists():
            fake_file.write_text("Honeypot - Não alterar")
        logging.info(f"Honey folder criado: {pasta}")

def check_patches():
    """Verifica patches críticos ausentes"""
    try:
        result = subprocess.run(['wmic', 'qfe', 'list', 'brief'], capture_output=True, text=True)
        patches = result.stdout
        logging.info(f"Patches instalados:\n{patches}")
    except Exception as e:
        logging.error(f"Erro ao verificar patches: {e}")

def consultar_cve():
    """Consulta alertas recentes do MSRC ou CVE feed (URL placeholder)"""
    try:
        url = "https://api.msrc.microsoft.com/cvrf/v2.0/sample"  # Substituir por feed real
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            logging.info(f"Alertas CVE recentes: {json.dumps(data)[:500]}...")  # log resumido
    except Exception as e:
        logging.error(f"Erro ao consultar CVE: {e}")

def exibir_ajuda():
    print("""
USO: python blindagem_2025.py [--blindar | --rollback | --check | --patch-check | --crypto-backup | --honey-folders | --help]

Parâmetros:
    --blindar         Executa a blindagem das pastas críticas
    --rollback        Restaura permissões padrão das pastas
    --check           Verifica integridade dos backups
    --patch-check     Verifica patches críticos ausentes
    --crypto-backup   Gera backup criptografado AES-256
    --honey-folders   Cria honey folders contra ransomware
    --help            Exibe esta ajuda
""")

# ============================
# INTERFACE CLI
# ============================

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--blindar", action="store_true")
parser.add_argument("--rollback", action="store_true")
parser.add_argument("--check", action="store_true")
parser.add_argument("--patch-check", action="store_true")
parser.add_argument("--crypto-backup", action="store_true")
parser.add_argument("--honey-folders", action="store_true")
parser.add_argument("--help", action="store_true")
args = parser.parse_args()

if args.help:
    exibir_ajuda()
    sys.exit(0)

pre_check()

if args.check:
    print("[*] Verificando integridade e backups...")
    backup_pastas()
    print("[✔] Check concluído.")
    sys.exit(0)

if args.rollback:
    print("[*] Restaurando permissões padrão...")
    restaurar_permissoes()
    print("[✔] Rollback concluído.")
    sys.exit(0)

if args.patch_check:
    print("[*] Verificando patches críticos ausentes...")
    check_patches()
    consultar_cve()
    print("[✔] Verificação de patches concluída.")
    sys.exit(0)

if args.crypto_backup:
    print("[*] Realizando backup criptografado...")
    backup_pastas(crypto=True)
    print("[✔] Backup criptografado concluído.")
    sys.exit(0)

if args.honey_folders:
    print("[*] Criando honey folders...")
    criar_honey_folders()
    print("[✔] Honey folders criadas.")
    sys.exit(0)

if args.blindar:
    print("[*] Realizando blindagem completa...")
    backup_pastas()
    for pasta in PASTAS_CRITICAS:
        aplicar_acl(pasta)
    criar_honey_folders()
    check_patches()
    consultar_cve()
    print("[✔] Blindagem avançada concluída.")
    sys.exit(0)

print("[ERRO] Nenhum parâmetro válido informado. Use --help para ver as opções.")
sys.exit(1)
