#!/usr/bin/env python3
"""
OSINT Enrichment Script v3
- Consulta AbuseIPDB e VirusTotal para IPs
- Async, retry, hash, logging, autenticação, instalação automática de módulos
"""

import sys
import subprocess

# ---------------------
# VERIFICAÇÃO DE DEPENDÊNCIAS
# ---------------------
required_modules = ["aiohttp", "PyYAML"]

def check_and_install_modules(modules):
    missing = []
    for module in modules:
        try:
            __import__(module.lower() if module != "PyYAML" else "yaml")
        except ImportError:
            missing.append(module)

    if missing:
        print(f"[INFO] Módulos ausentes detectados: {', '.join(missing)}")
        print("[INFO] Instalando dependências automaticamente...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing)
            print("[INFO] Instalação concluída. Continue a execução do script.")
        except subprocess.CalledProcessError:
            print("[ERRO] Falha ao instalar módulos. Instale manualmente:")
            print(f"pip install {' '.join(missing)}")
            sys.exit(1)

check_and_install_modules(required_modules)

# Agora podemos importar com segurança
import os
import csv
import json
import argparse
import logging
import hashlib
import re
import asyncio
import aiohttp
import yaml
from typing import Dict, List, Optional, Union

# ---------------------
# CONFIGURAÇÕES GERAIS
# ---------------------
DEFAULT_CONFIG_PATH = "config.yaml"
LOG_FILE = "osint_enrichment.log"
HASH_FILE_SUFFIX = ".sha256"
AUTH_PASSWORD_ENV = "OSINT_AUTH_PASSWORD"

IPV4_PATTERN = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.|$)){4}$")

# ---------------------
# LOGGER
# ---------------------
logger = logging.getLogger("OSINT")
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

ch = logging.StreamHandler()
ch.setFormatter(formatter)
logger.addHandler(ch)

fh = logging.FileHandler(LOG_FILE)
fh.setFormatter(formatter)
logger.addHandler(fh)

# ---------------------
# FUNÇÕES UTILITÁRIAS
# ---------------------
def is_valid_ipv4(ip: str) -> bool:
    return IPV4_PATTERN.match(ip) is not None

def calc_file_hash(file_path: str) -> str:
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        logger.error(f"Erro ao calcular hash do arquivo {file_path}: {e}")
        return ""

def save_hash_to_file(hash_str: str, filename: str):
    try:
        with open(filename, 'w') as f:
            f.write(hash_str)
        logger.info(f"Hash de integridade salvo em {filename}")
    except Exception as e:
        logger.error(f"Erro ao salvar hash no arquivo {filename}: {e}")

async def async_retry(func, *args, retries=3, backoff_in_seconds=2, **kwargs):
    for attempt in range(1, retries+1):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            wait = backoff_in_seconds ** attempt
            logger.warning(f"Tentativa {attempt} falhou: {e}. Re-tentando em {wait}s...")
            await asyncio.sleep(wait)
    raise Exception(f"Todas as {retries} tentativas falharam para a função {func.__name__}")

def authenticate(password_arg: Optional[str]) -> bool:
    expected = os.getenv(AUTH_PASSWORD_ENV)
    if expected is None:
        logger.warning("Variável de ambiente OSINT_AUTH_PASSWORD não configurada. Pulando autenticação.")
        return True
    if password_arg is None:
        logger.error("Senha não fornecida. Uso obrigatório no modo autenticado.")
        return False
    if password_arg != expected:
        logger.error("Senha incorreta.")
        return False
    logger.info("Autenticação realizada com sucesso.")
    return True

def validate_file_hash(file_path: str, hash_path: str) -> bool:
    if not os.path.exists(file_path) or not os.path.exists(hash_path):
        logger.warning("Arquivo ou hash para validação não encontrado.")
        return False
    file_hash = calc_file_hash(file_path)
    try:
        with open(hash_path, 'r') as f:
            stored_hash = f.read().strip()
        if file_hash == stored_hash:
            logger.info("Validação de integridade do arquivo: OK")
            return True
        else:
            logger.error("Falha na validação de integridade do arquivo!")
            return False
    except Exception as e:
        logger.error(f"Erro ao validar hash: {e}")
        return False

# ---------------------
# CLIENTES OSINT
# ---------------------
class AbuseIPDBClient:
    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str, max_age_days: int = 90):
        self.api_key = api_key
        self.max_age_days = max_age_days
        self.headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }

    async def query_ip(self, session: aiohttp.ClientSession, ip: str) -> Dict[str, Union[str,int,bool]]:
        if not is_valid_ipv4(ip):
            return {'error': 'IP inválido', 'ip': ip}
        params = {'ipAddress': ip, 'maxAgeInDays': self.max_age_days}
        async with session.get(self.BASE_URL, headers=self.headers, params=params, timeout=10) as response:
            if response.status == 429:
                await asyncio.sleep(60)
                return await self.query_ip(session, ip)
            elif response.status != 200:
                text = await response.text()
                return {'error': f'HTTP {response.status}', 'ip': ip}
            data = await response.json()
            return {
                'ip': ip,
                'abuseConfidenceScore': data['data'].get('abuseConfidenceScore', 0),
                'country': data['data'].get('countryCode', 'N/A'),
                'isPublic': data['data'].get('isPublic', False),
                'usageType': data['data'].get('usageType', 'N/A'),
                'totalReports': data['data'].get('totalReports', 0)
            }

class VirusTotalClient:
    BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {
            'x-apikey': self.api_key
        }

    async def query_ip(self, session: aiohttp.ClientSession, ip: str) -> Dict[str, Union[str,int]]:
        if not is_valid_ipv4(ip):
            return {'error': 'IP inválido', 'ip': ip}
        url = self.BASE_URL + ip
        async with session.get(url, headers=self.headers, timeout=10) as response:
            if response.status == 429:
                await asyncio.sleep(60)
                return await self.query_ip(session, ip)
            elif response.status != 200:
                return {'error': f'HTTP {response.status}', 'ip': ip}
            data = await response.json()
            attributes = data.get('data', {}).get('attributes', {})
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            return {
                'ip': ip,
                'malicious': last_analysis_stats.get('malicious', 0),
                'suspicious': last_analysis_stats.get('suspicious', 0),
                'harmless': last_analysis_stats.get('harmless', 0)
            }

# ---------------------
# PROCESSAMENTO
# ---------------------
async def process_ips(ips: List[str],
                      abuse_client: Optional[AbuseIPDBClient],
                      vt_client: Optional[VirusTotalClient]) -> List[Dict]:
    results = []
    async with aiohttp.ClientSession() as session:
        tasks = [enrich_ip(ip, session, abuse_client, vt_client) for ip in ips if ip.strip()]
        results = await asyncio.gather(*tasks)
    return results

async def enrich_ip(ip: str, session: aiohttp.ClientSession,
                    abuse_client: Optional[AbuseIPDBClient],
                    vt_client: Optional[VirusTotalClient]) -> Dict:
    abuse_data = {}
    vt_data = {}
    try:
        if abuse_client:
            abuse_data = await async_retry(abuse_client.query_ip, session, ip)
    except Exception as e:
        logger.error(f"Erro AbuseIPDB para {ip}: {e}")
    try:
        if vt_client:
            vt_data = await async_retry(vt_client.query_ip, session, ip)
    except Exception as e:
        logger.error(f"Erro VirusTotal para {ip}: {e}")
    combined = {'ip': ip}
    combined.update(abuse_data)
    combined.update(vt_data)
    return combined

def save_results(results: List[Dict], output_file: str, output_format: str = 'csv'):
    if output_format.lower() == 'json':
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
    else:
        all_keys = sorted(set().union(*(r.keys() for r in results)))
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=all_keys)
            writer.writeheader()
            writer.writerows(results)
    logger.info(f"Resultados salvos em {output_file}")

def load_config(file_path: str) -> Dict:
    with open(file_path, 'r') as f:
        return yaml.safe_load(f)

# ---------------------
# MAIN
# ---------------------
def main():
    parser = argparse.ArgumentParser(description="OSINT enrichment (IPs) com AbuseIPDB e VirusTotal")
    parser.add_argument("-c", "--config", default=DEFAULT_CONFIG_PATH, help="Arquivo YAML config")
    parser.add_argument("-i", "--input", required=True, help="Arquivo CSV com IPs")
    parser.add_argument("-o", "--output", required=True, help="Arquivo de saída (CSV ou JSON)")
    parser.add_argument("-p", "--password", help="Senha para autenticação (se OSINT_AUTH_PASSWORD setado)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo verboso DEBUG")
    parser.add_argument("--validate-input-hash", action="store_true", help="Validar hash do arquivo de entrada")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if not authenticate(args.password):
        sys.exit(1)

    if args.validate_input_hash:
        if not validate_file_hash(args.input, args.input + HASH_FILE_SUFFIX):
            logger.error("Integridade do arquivo de entrada inválida.")
            sys.exit(1)

    config = load_config(args.config)
    abuse_key = os.getenv("ABUSEIPDB_API_KEY") or config.get('abuseipdb_api_key')
    vt_key = os.getenv("VIRUSTOTAL_API_KEY") or config.get('virustotal_api_key')

    abuse_client = AbuseIPDBClient(abuse_key) if abuse_key else None
    vt_client = VirusTotalClient(vt_key) if vt_key else None

    with open(args.input, 'r') as f:
        ips = [line.strip() for line in f if line.strip()]

    results = asyncio.run(process_ips(ips, abuse_client, vt_client))
    output_format = 'json' if args.output.lower().endswith('.json') else 'csv'
    save_results(results, args.output, output_format)

    hash_str = calc_file_hash(args.output)
    if hash_str:
        save_hash_to_file(hash_str, args.output + HASH_FILE_SUFFIX)

    logger.info("Processo concluído com sucesso.")

if __name__ == "__main__":
    main()
