from elasticsearch import Elasticsearch
import requests
import re
import time
import config
import logging
from logging.handlers import TimedRotatingFileHandler

# Setup logging ke file lokal dengan rotating harian
logger = logging.getLogger("tpot_alerts")
logger.setLevel(logging.INFO)
handler = TimedRotatingFileHandler(
    "alerts.log", when="midnight", interval=1, backupCount=7, encoding="utf-8"
)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

# Koneksi ke Elasticsearch
es = Elasticsearch(
    [config.ES_HOST],
    basic_auth=(config.ES_USER, config.ES_PASS)
)

def fetch_new_alerts(last_ts):
    res = es.search(
        index="tpot-*",
        query={"range": {"@timestamp": {"gt": last_ts}}},
        sort=[{"@timestamp": {"order": "asc"}}],
        size=10
    )
    return res['hits']['hits']

def classify_event(event):
    src = event.get('_source', {})
    text = " ".join(str(v).lower() for v in src.values())

    # --- Sudah ada ---
    if re.search(r'failed password|authentication failure|sshd', text):
        return ("SSH brute-force", "Block IP temporer, aktifkan fail2ban")
    if re.search(r'sql syntax|union select|or 1=1', text):
        return ("SQL Injection", "Gunakan prepared statements, WAF")
    if re.search(r'cmd.exe|powershell|wget http', text):
        return ("Remote Command Execution", "Isolasi server, update patch")

    # --- Tambahan OWASP Top 10 ---
    # A01: Broken Access Control
    if re.search(r'forbidden|unauthorized|access denied', text):
        return ("Broken Access Control", "Periksa aturan ACL & otorisasi aplikasi")

    # A02: Cryptographic Failures
    if re.search(r'invalid certificate|ssl handshake failure|weak cipher', text):
        return ("Cryptographic Failures", "Gunakan TLS modern, nonaktifkan algoritma lemah")

    # A03: Injection (selain SQL Injection)
    if re.search(r'<script>|<img src=|onerror=|eval\(|alert\(', text):
        return ("XSS Injection", "Aktifkan sanitasi input & Content Security Policy")

    # A04: Insecure Design
    if re.search(r'default password|test account|hardcoded password', text):
        return ("Insecure Design", "Hapus akun default, lakukan threat modeling")

    # A05: Security Misconfiguration
    if re.search(r'index of /|exposed config|directory listing', text):
        return ("Security Misconfiguration", "Nonaktifkan directory listing, amankan konfigurasi")

    # A06: Vulnerable and Outdated Components
    if re.search(r'outdated version|cve-|end of life', text):
        return ("Vulnerable Components", "Update library & lakukan patch management")

    # A07: Identification and Authentication Failures
    if re.search(r'multiple login failures|weak password|no 2fa', text):
        return ("Auth Failures", "Gunakan MFA, enforce password policy")

    # A08: Software and Data Integrity Failures
    if re.search(r'supply chain|tampered|checksum mismatch', text):
        return ("Data Integrity Failures", "Verifikasi tanda tangan digital, gunakan CI/CD aman")

    # A09: Security Logging and Monitoring Failures
    if re.search(r'no logging|log failure|monitoring disabled', text):
        return ("Logging/Monitoring Failures", "Aktifkan audit log & SIEM monitoring")

    # A10: Server-Side Request Forgery (SSRF)
    if re.search(r'curl http|file_get_contents\(|ssrf attempt', text):
        return ("SSRF Attack", "Validasi URL target, gunakan allowlist domain")

    return ("Unknown", "Periksa log secara manual")

def send_telegram(message):
    url = f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": config.TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }
    r = requests.post(url, json=payload)
    print(f"Telegram send status: {r.status_code}, {r.text}")

if __name__ == "__main__":
    last_ts = "now-5m"
    while True:
        try:
            alerts = fetch_new_alerts(last_ts)
            for a in alerts:
                attack_type, recommendation = classify_event(a)
                ts = a['_source'].get('@timestamp', '')
                src_ip = a['_source'].get('src_ip', 'unknown')
                msg = (
                    f"🚨 *T-Pot Alert* 🚨\n"
                    f"🕒 Waktu: {ts}\n"
                    f"🔎 Jenis: {attack_type}\n"
                    f"🌐 IP: {src_ip}\n"
                    f"✅ Rekomendasi: {recommendation}"
                )
                send_telegram(msg)
                logger.info(msg)
                last_ts = ts
        except Exception as e:
            print(f"Error: {e}")
        time.sleep(30)
