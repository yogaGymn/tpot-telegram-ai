from elasticsearch import Elasticsearch
import requests
import re
import time
import config

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

    if re.search(r'failed password|authentication failure|sshd', text):
        return ("SSH brute-force", "Block IP temporer, aktifkan fail2ban")
    if re.search(r'sql syntax|union select|or 1=1', text):
        return ("SQL Injection", "Gunakan prepared statements, WAF")
    if re.search(r'cmd.exe|powershell|wget http', text):
        return ("Remote Command Execution", "Isolasi server, update patch")

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
                last_ts = ts
        except Exception as e:
            print(f"Error: {e}")
        time.sleep(30)
