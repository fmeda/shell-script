#!/usr/bin/env python3
"""
IoT Security Sentinel - Corporate Version
Autor: Fabiano Aparecido
Descrição: Monitoramento avançado de dispositivos IoT com fingerprinting, CVEs, alertas e relatórios.
Inclui pré-check automático de módulos e CLI amigável.
"""

import subprocess
import sys

# --------------------------
# Pré-check de módulos
# --------------------------
REQUIRED_MODULES = [
    "requests",
    "mac_vendor_lookup",
    "tqdm",
    "cryptography",
    "fpdf"
]

def install_module(module):
    """Tenta instalar o módulo via pip."""
    print(f"[INFO] Instalando módulo ausente: {module}")
    subprocess.check_call([sys.executable, "-m", "pip", "install", module])

for module in REQUIRED_MODULES:
    try:
        __import__(module)
    except ImportError:
        install_module(module)

# --------------------------
# Imports principais
# --------------------------
import os
import argparse
import logging
import socket
import threading
import time
import hashlib
import ipaddress
import csv
from queue import Queue
from datetime import datetime
from mac_vendor_lookup import MacLookup
from tqdm import tqdm
from cryptography.fernet import Fernet
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from fpdf import FPDF
import requests

# --------------------------
# Configurações
# --------------------------
LOG_FILE = "IoTSentinel.log"
KEY_FILE = "iot_log.key"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY")
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")
EMAIL_HOST = os.environ.get("EMAIL_HOST")
EMAIL_PORT = int(os.environ.get("EMAIL_PORT", 587))
EMAIL_USER = os.environ.get("EMAIL_USER")
EMAIL_PASS = os.environ.get("EMAIL_PASS")
ALERT_LEVEL = "WARNING"

# --------------------------
# Logging criptografado
# --------------------------
def generate_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return key

FERNET = Fernet(generate_key())

def secure_log(message):
    encrypted = FERNET.encrypt(message.encode())
    with open(LOG_FILE, "ab") as f:
        f.write(encrypted + b"\n")

# --------------------------
# Alertas
# --------------------------
def send_telegram(message):
    if TELEGRAM_TOKEN and TELEGRAM_CHAT_ID:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        try:
            requests.post(url, data={"chat_id": TELEGRAM_CHAT_ID, "text": message})
        except:
            pass

def send_email(subject, message):
    if EMAIL_HOST and EMAIL_USER:
        msg = MIMEMultipart()
        msg["From"] = EMAIL_USER
        msg["To"] = EMAIL_USER
        msg["Subject"] = subject
        msg.attach(MIMEText(message, "plain"))
        try:
            server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
            server.quit()
        except:
            pass

def send_alert(message, level="WARNING"):
    print(f"[{level}] {message}")
    secure_log(f"{datetime.now()} - {level} - {message}")
    send_telegram(message)
    if level in ["WARNING", "CRITICAL"]:
        send_email(f"IoT Sentinel Alert - {level}", message)

# --------------------------
# Fingerprinting
# --------------------------
def hash_value(value):
    return hashlib.sha256(value.encode()).hexdigest()

def get_mac_vendor(mac):
    try:
        return MacLookup().lookup(mac)
    except:
        return "Desconhecido"

def fingerprint_device(ip, anonymize=True):
    info = {"ip": ip, "vendor": "Desconhecido", "open_ports": []}
    common_ports = [22,23,80,443,8080]
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        if sock.connect_ex((ip, port)) == 0:
            info["open_ports"].append(port)
        sock.close()
    try:
        arp_output = subprocess.check_output(["arp", "-n", ip]).decode()
        mac = arp_output.split()[3]
        vendor = get_mac_vendor(mac)
        info["vendor"] = vendor
        if anonymize:
            info["ip"] = hash_value(ip)
            info["mac_hash"] = hash_value(mac)
        else:
            info["mac"] = mac
    except:
        info["vendor"] = "Desconhecido"
    secure_log(f"Fingerprint: {info}")
    return info

# --------------------------
# CVE Check
# --------------------------
def check_cves(device_info):
    alerts = []
    for port in device_info["open_ports"]:
        keyword = f"{device_info['vendor']} {port}"
        params = {"keyword": keyword, "resultsPerPage":5}
        if NVD_API_KEY:
            params["apiKey"] = NVD_API_KEY
        try:
            r = requests.get(NVD_API_URL, params=params, timeout=10)
            data = r.json()
            cves = data.get("result", {}).get("CVE_Items", [])
            for cve in cves:
                cve_id = cve["cve"]["CVE_data_meta"]["ID"]
                desc = cve["cve"]["description"]["description_data"][0]["value"]
                message = f"CVE detectada {device_info['ip']}: {cve_id} - {desc[:100]}..."
                send_alert(message, "CRITICAL")
                alerts.append(message)
        except:
            pass
    return alerts

# --------------------------
# Scan IP / Network
# --------------------------
def scan_ip(ip, ports_check=False, cve_check=False, dry_run=False):
    if dry_run:
        print(f"[DRY-RUN] Simulando scan {ip}")
        secure_log(f"Dry-run scan {ip}")
        return
    try:
        response = subprocess.run(["ping","-c","1","-W","1",ip], stdout=subprocess.DEVNULL)
        if response.returncode == 0:
            print(f"[DISCOVERED] {ip}")
            info = fingerprint_device(ip)
            if ports_check:
                secure_log(f"Portas abertas: {info['open_ports']}")
            if cve_check:
                check_cves(info)
    except:
        secure_log(f"Erro scan {ip}")

def worker(queue, ports_check, cve_check, dry_run):
    while not queue.empty():
        ip = queue.get()
        scan_ip(ip, ports_check, cve_check, dry_run)
        queue.task_done()

def scan_network(network_cidr, ports_check=False, cve_check=False, dry_run=False, max_threads=20):
    try:
        network = ipaddress.ip_network(network_cidr, strict=False)
    except ValueError:
        print("[ERROR] CIDR inválido")
        sys.exit(1)
    queue = Queue()
    for ip in network.hosts():
        queue.put(str(ip))
    threads = []
    for _ in range(min(max_threads, queue.qsize())):
        t = threading.Thread(target=worker, args=(queue, ports_check, cve_check, dry_run))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    print("[SCAN COMPLETO] Todos os hosts verificados.")
    generate_report_csv(network_cidr)

# --------------------------
# Relatórios CSV e PDF
# --------------------------
def generate_report_csv(network_cidr):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"iot_report_{timestamp}.csv"
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["IP/MAC Hash","Vendor","Open Ports"])
        try:
            with open(LOG_FILE, "rb") as logf:
                for line in logf:
                    decrypted = FERNET.decrypt(line.strip()).decode()
                    if "Fingerprint" in decrypted:
                        info = decrypted.split("Fingerprint: ")[1]
                        writer.writerow([info])
        except:
            pass
    print(f"[REPORT CSV] Gerado: {filename}")
    generate_report_pdf(filename)

def generate_report_pdf(csv_file):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200,10,"IoT Security Sentinel Report",ln=True,align="C")
    pdf.ln(10)
    try:
        with open(csv_file,"r") as f:
            for line in f:
                pdf.cell(200,5,line.strip(),ln=True)
    except:
        pass
    pdf_filename = csv_file.replace(".csv",".pdf")
    pdf.output(pdf_filename)
    print(f"[REPORT PDF] Gerado: {pdf_filename}")

# --------------------------
# Monitoramento contínuo
# --------------------------
def monitor_network(network_cidr, ports_check=False, cve_check=False, interval=300, dry_run=False):
    while True:
        secure_log("Iniciando monitoramento contínuo...")
        scan_network(network_cidr, ports_check, cve_check, dry_run)
        time.sleep(interval)

# --------------------------
# Permissões
# --------------------------
def check_permissions():
    if os.geteuid() != 0:
        print("[WARNING] Para ARP e fingerprint completos, execute como root.")
        secure_log("Executado sem privilégios de root")

# --------------------------
# CLI aprimorada
# --------------------------
def main():
    parser = argparse.ArgumentParser(
        description="IoT Security Sentinel - Corporate",
        epilog="Exemplo de uso: python IoTSentinel.py -r 192.168.1.0/24 -p -v"
    )
    parser.add_argument("-r","--range",help="Faixa de IP/CIDR (ex:192.168.1.0/24)")
    parser.add_argument("-p","--ports",action="store_true",help="Verificar portas abertas")
    parser.add_argument("-v","--cve",action="store_true",help="Verificação de CVEs")
    parser.add_argument("-c","--continuous",action="store_true",help="Monitoramento contínuo")
    parser.add_argument("-i","--interval",type=int,default=300,help="Intervalo de monitoramento contínuo")
    parser.add_argument("--dry-run",action="store_true",help="Simula scan sem conexões reais")
    parser.add_argument("--threads",type=int,default=20,help="Número máximo de threads simultâneas")

    # Se nenhum argumento for passado, mostra ajuda
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if not args.range and not args.continuous:
        print("\n[ERROR] Você precisa informar a faixa de IP com -r/--range ou ativar o monitoramento contínuo com -c\n")
        parser.print_help()
        sys.exit(1)

    check_permissions()
    
    if args.continuous:
        monitor_network(args.range, args.ports, args.cve, args.interval, args.dry_run)
    else:
        scan_network(args.range, args.ports, args.cve, args.dry_run, args.threads)

if __name__ == "__main__":
    main()
