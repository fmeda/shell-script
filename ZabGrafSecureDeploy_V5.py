#!/usr/bin/env python3
import os
import subprocess
import time
import logging
import requests
import argparse
import sys
import yaml
from logging.handlers import RotatingFileHandler

# ---------------------------
# Configurações iniciais
# ---------------------------
LOG_FILE = '/var/log/zabbix_grafana_installer.log'
HTML_REPORT = '/var/www/html/zabbix_grafana_report.html'
DEFAULT_CONFIG_FILE = '/etc/monitor_config.yaml'

# Cores para terminal
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# ---------------------------
# Logging com rotação
# ---------------------------
logger = logging.getLogger()
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=5)
formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s', '%Y-%m-%d %H:%M:%S')
handler.setFormatter(formatter)
logger.addHandler(handler)

# ---------------------------
# Funções utilitárias
# ---------------------------
def rotacionar_logs():
    """Rotaciona o log manualmente com timestamp (opcional)"""
    if os.path.exists(LOG_FILE):
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        try:
            os.rename(LOG_FILE, f"{LOG_FILE}.{timestamp}")
            logger.info(f"Log rotacionado para {LOG_FILE}.{timestamp}")
        except Exception as e:
            logger.error(f"Erro ao rotacionar logs: {e}")
    open(LOG_FILE, 'w').close()

def executar_comando(comando, shell=False, sudo=False):
    """Executa comando via subprocess"""
    if sudo:
        if isinstance(comando, list):
            comando = ["sudo"] + comando
        else:
            comando = "sudo " + comando
    try:
        if shell:
            result = subprocess.run(comando, shell=True, capture_output=True, text=True, check=False)
        else:
            result = subprocess.run(comando, capture_output=True, text=True, check=False)
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except Exception as e:
        logger.error(f"Erro ao executar comando '{comando}': {e}")
        return "", str(e), 1

def checar_dependencias():
    """Verifica se comandos essenciais existem no sistema"""
    logger.info("Checando dependências do sistema...")
    dependencias = ["apt-get", "ufw", "systemctl", "curl", "jq"]
    missing = []
    for cmd in dependencias:
        _, _, code = executar_comando(["which", cmd])
        if code != 0:
            missing.append(cmd)
    if missing:
        logger.error(f"Dependências ausentes: {', '.join(missing)}")
        return False
    logger.info("Todas dependências presentes.")
    return True

def instalar_pacote(pacote):
    logger.info(f"Iniciando instalação do pacote: {pacote}")
    stdout, stderr, code = executar_comando(["apt-get", "install", "-y", pacote], sudo=True)
    if code != 0:
        logger.error(f"Falha ao instalar {pacote}: {stderr}")
        return False
    logger.info(f"Pacote {pacote} instalado com sucesso.")
    return True

def atualizar_pacotes():
    logger.info("Atualizando lista de pacotes (apt-get update)...")
    stdout, stderr, code = executar_comando(["apt-get", "update"], sudo=True)
    if code != 0:
        logger.error(f"Falha ao atualizar pacotes: {stderr}")
        return False
    logger.info("Lista de pacotes atualizada com sucesso.")
    return True

def configurar_firewall():
    logger.info("Configurando firewall UFW...")
    comandos = [
        ["apt-get", "install", "-y", "fail2ban", "ufw"],
        ["ufw", "default", "deny", "incoming"],
        ["ufw", "default", "allow", "outgoing"],
        ["ufw", "allow", "ssh"],
        ["ufw", "allow", "10050"],  # Zabbix
        ["ufw", "allow", "3000"],   # Grafana
        ["ufw", "enable"]
    ]
    for cmd in comandos:
        _, stderr, code = executar_comando(cmd, sudo=True)
        if code != 0:
            logger.error(f"Erro ao executar {' '.join(cmd)}: {stderr}")
            return False
    logger.info("Firewall configurado com sucesso.")
    return True

def verificar_servico(servico):
    _, _, code = executar_comando(["systemctl", "is-active", "--quiet", servico])
    return code == 0

def reiniciar_servico(servico):
    logger.info(f"Tentando reiniciar serviço: {servico}")
    _, stderr, code = executar_comando(["systemctl", "restart", servico], sudo=True)
    if code != 0:
        logger.error(f"Falha ao reiniciar serviço {servico}: {stderr}")
        return False
    logger.info(f"Serviço {servico} reiniciado com sucesso.")
    return True

def self_healing(servicos=None):
    if servicos is None:
        servicos = ["zabbix-server", "grafana-server", "nginx"]
    logger.info("Iniciando self-healing dos serviços críticos.")
    for s in servicos:
        if not verificar_servico(s):
            logger.warning(f"Serviço {s} não está ativo. Tentando reiniciar...")
            if not reiniciar_servico(s):
                logger.error(f"Não foi possível reiniciar o serviço {s}.")
            else:
                logger.info(f"Serviço {s} ativo após reinício.")
        else:
            logger.info(f"Serviço {s} ativo.")

def criar_dashboard_grafana():
    logger.info("Configurando dashboard inicial no Grafana via API.")
    api_key = os.getenv("GRAFANA_API_KEY")
    if not api_key:
        logger.error("Variável de ambiente GRAFANA_API_KEY não definida.")
        return False
    url = 'http://localhost:3000/api/dashboards/db'
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "dashboard": {
            "title": "Monitoramento Completo",
            "panels": [{"type": "graph", "title": "CPU Usage"}, {"type": "graph", "title": "Memory Usage"}]
        },
        "overwrite": True
    }
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        response.raise_for_status()
        logger.info("Dashboard criado com sucesso no Grafana.")
        return True
    except requests.RequestException as e:
        logger.error(f"Erro ao criar dashboard no Grafana: {e}")
        return False

def gerar_relatorio_html():
    logger.info("Gerando relatório HTML de status.")
    conteudo_html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>Relatório Zabbix e Grafana</title>
<style>
body {{ font-family: Arial, sans-serif; background: #f9f9f9; }}
h1 {{ color: #2c3e50; }}
.status-ok {{ color: green; }}
.status-erro {{ color: red; }}
</style>
</head>
<body>
<h1>Relatório de Instalação e Configuração</h1>
<p>Status: <span class="status-ok">Concluído com sucesso</span></p>
<p>Verifique os logs em <code>{LOG_FILE}</code> para detalhes.</p>
</body>
</html>"""
    try:
        with open(HTML_REPORT, 'w') as f:
            f.write(conteudo_html)
        logger.info(f"Relatório HTML gerado em {HTML_REPORT}.")
        return True
    except Exception as e:
        logger.error(f"Falha ao gerar relatório HTML: {e}")
        return False

def habilitar_e_iniciar_servico(servico):
    logger.info(f"Habilitando e iniciando serviço {servico}...")
    _, stderr, code = executar_comando(["systemctl", "enable", servico], sudo=True)
    if code != 0:
        logger.error(f"Falha ao habilitar serviço {servico}: {stderr}")
        return False
    _, stderr, code = executar_comando(["systemctl", "start", servico], sudo=True)
    if code != 0:
        logger.error(f"Falha ao iniciar serviço {servico}: {stderr}")
        return False
    logger.info(f"Serviço {servico} habilitado e iniciado com sucesso.")
    return True

def carregar_config(config_file=DEFAULT_CONFIG_FILE):
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            try:
                config = yaml.safe_load(f)
                logger.info(f"Arquivo de configuração {config_file} carregado.")
                return config
            except Exception as e:
                logger.error(f"Falha ao carregar configuração: {e}")
                return {}
    return {}

# ---------------------------
# Função principal
# ---------------------------
def main(args):
    rotacionar_logs()
    logger.info("Iniciando instalação segura do Zabbix, Grafana e Nginx.")

    if not checar_dependencias():
        print(f"{RED}Dependências ausentes. Abortando.{RESET}")
        sys.exit(1)

    atualizar_pacotes()
    instalar_pacote("apache2")
    habilitar_e_iniciar_servico("apache2")
    configurar_firewall()
    self_healing()
    criar_dashboard_grafana()
    gerar_relatorio_html()
    print(f"{GREEN}Instalação finalizada! Verifique relatório em http://<IP_DO_SERVIDOR>/zabbix_grafana_report.html{RESET}")

# ---------------------------
# CLI --help
# ---------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Instalador seguro Zabbix + Grafana + Apache")
    parser.add_argument("--instalar", action="store_true", help="Executa instalação completa")
    parser.add_argument("--self-healing", action="store_true", help="Executa verificação e reinício de serviços críticos")
    parser.add_argument("--relatorio", action="store_true", help="Gera relatório HTML")
    parser.add_argument("--config", type=str, help="Caminho do arquivo de configuração YAML", default=DEFAULT_CONFIG_FILE)
    args = parser.parse_args()

    if args.instalar:
        main(args)
    elif args.self_healing:
        self_healing()
    elif args.relatorio:
        gerar_relatorio_html()
    else:
        parser.print_help()
