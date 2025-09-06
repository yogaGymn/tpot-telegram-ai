from elasticsearch import Elasticsearch
import requests
import re
import time
from collections import defaultdict
import config

# Koneksi ke Elasticsearch
#es = Elasticsearch(config.ES_HOST)
es = Elasticsearch(
    [config.ES_HOST],
    basic_auth=(config.ES_USER, config.ES_PASS)
)

# Simpan jumlah serangan per IP
attack_counter = defaultdict(int)

LOG_FILE = "alerts.log"

# ------------------ Fungsi Klasifikasi ------------------ #
def classify_event(event):
    src = event.get('_source', {})
    text = " ".join(str(v).lower() for v in src.values())
    src_ip = src.get('src_ip', 'unknown')

    # Hitung jumlah serangan IP
    attack_counter[src_ip] += 1
    hit_count = attack_counter[src_ip]

    # Default nilai
    attack_type = "Suspicious Activity"
    recommendation = "Analisis lebih lanjut, aktifkan IDS/WAF, periksa konfigurasi server"
    severity = "Low"
    # Deteksi pola serangan
    if re.search(r'failed password|authentication failure|sshd', text):
        attack_type = "SSH Brute Force"
        recommendation = "Aktifkan fail2ban atau batasi login SSH, gunakan autentikasi kunci publik"
        severity = "High"
    elif re.search(r'sql syntax|union select|or 1=1', text):
        attack_type = "SQL Injection"
        recommendation = "Gunakan prepared statements, validasi input, dan aktifkan WAF"
        severity = "High"
    elif re.search(r'cmd.exe|powershell|wget http', text):
        attack_type = "Remote Command Execution"
        recommendation = "Isolasi server, update patch, dan audit script yang berjalan"
        severity = "High"
    elif re.search(r'nmap|masscan|port scan', text):
        attack_type = "Port Scanning"
        recommendation = "Perkuat firewall dan aktifkan IDS/IPS untuk mendeteksi pemindaian"
        severity = "Medium"
    elif re.search(r'<script>|javascript:|onerror=', text):
        attack_type = "XSS Attack"
        recommendation = "Aktifkan Content Security Policy (CSP) dan filter input pengguna"
        severity = "Medium"
    elif re.search(r'denial of service|slowloris|flood', text):
        attack_type = "DoS Attack"
        recommendation = "Gunakan rate limiting, optimalkan server, dan aktifkan proteksi DoS"
        severity = "High"
    elif re.search(r'/etc/passwd|shadow file|privilege escalation', text):
        attack_type = "Privilege Escalation Attempt"
        recommendation = "Segera periksa hak akses, update patch, dan audit keamanan sistem"
        severity = "High"
   else:
        # Heuristic untuk unknown attack
        if re.search(r'exec|shell|rm -rf|chmod|wget|curl', text):
            severity = "High"
            recommendation = "Kemungkinan Remote Command Execution, periksa log dan isolasi server"
        elif re.search(r'error|failed|invalid', text):
            severity = "Medium"
            recommendation = "Banyak error terdeteksi, mungkin probing atau fuzzing, periksa aplikasi"
        else:
            severity = "Low"
            recommendation = "Aktivitas tidak biasa, pantau terus dan lakukan analisis lebih lanjut"

    # Jika IP sering menyerang → naikkan severity (tanpa blokir)
    if hit_count > 5:
        severity = "High"
        recommendation += f" | IP ini sudah {hit_count} kali mencoba, tingkatkan monitoring."

    return attack_type, recommendation, severity, hit_count

# ------------------ Emoji untuk Severity ------------------ #
def emoji_severity(severity):
    if severity == "High":
        return "🔴 High"
    elif severity == "Medium":
        return "🟡 Medium"
    else:
        return "🟢 Low"

# ------------------ Fetch Alerts dari Elasticsearch ------------------ #
def fetch_new_alerts(last_ts):
    res = es.search(
        index="tpot-*",
        query={"range": {"@timestamp": {"gt": last_ts}}},
        sort=[{"@timestamp": {"order": "asc"}}],
        size=10
    )
    return res['hits']['hits']

# ------------------ Kirim ke Telegram ------------------ #
def send_telegram(message):
    url = f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": config.TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }
    r = requests.post(url, json=payload)
    print(f"Telegram send status: {r.status_code}, {r.text}")

# ------------------ Simpan ke File Log ------------------ #
def log_alert(ts, src_ip, attack_type, severity, hit_count, recommendation):
    with open(LOG_FILE, "a") as f:
        log_msg = f"[{ts}] IP: {src_ip} | Type: {attack_type} | Severity: {severity} | Hits: {hit_count} | Rekomendasi: {>
        f.write(log_msg)

# ------------------ Main Loop ------------------ #
if __name__ == "__main__":
    last_ts = "now-5m"
    while True:
        try:
            alerts = fetch_new_alerts(last_ts)
            for a in alerts:
                attack_type, recommendation, severity, hit_count = classify_event(a)
                ts = a['_source'].get('@timestamp', '')
                src_ip = a['_source'].get('src_ip', 'unknown')

                severity_display = emoji_severity(severity)

                msg = (
                    f"🚨 *T-Pot Alert* 🚨\n"
                    f"🕒 Waktu: {ts}\n"
                    f"🔍 Jenis: {attack_type}\n"
                    f"🌐 IP: {src_ip}\n"
                    f"🔥 Severity: *{severity_display}*\n"
                    f"📊 Total Hit dari IP ini: {hit_count}\n"
                    f"✅ Rekomendasi: {recommendation}"
                )

                # Kirim ke Telegram
                send_telegram(msg)
              # Simpan ke file log
                log_alert(ts, src_ip, attack_type, severity, hit_count, recommendation)

                last_ts = ts
        except Exception as e:
            print(f"Error: {e}")
        time.sleep(30)
