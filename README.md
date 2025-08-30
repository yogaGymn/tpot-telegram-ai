# 🛡️ T-Pot Alert to Telegram Bot

Proyek ini berfungsi untuk **mendeteksi serangan honeypot T-Pot** kemudian mengirimkan notifikasi **real-time ke Telegram**.  
Dengan bot ini, admin bisa langsung tahu jenis serangan dan rekomendasi tindakan tanpa harus membuka dashboard T-Pot. 🚀

---

## ✨ Fitur
- 🔍 Mengambil log serangan dari ** (T-Pot)**
- 🤖 Mengklasifikasikan jenis serangan secara otomatis (SSH Brute-force, SQL Injection, RCE, dll.)
- 📲 Mengirimkan notifikasi langsung ke **Telegram Bot**
- ⏱️ Monitoring real-time (cek log setiap 30 detik)

## ⚙️ Konfigurasi

### T-Pot
Edit `config.py` sesuai dengan server T-Pot kamu:
```python
ES_HOST = "http://IP_TPOT"
ES_USER = "root"
ES_PASS = "password_TPOT"

🚀 Jalankan monitoring honeypot
python3 main.py

🚨 T-Pot Alert 🚨
🕒 Waktu: 2025-08-30T12:34:56Z
🔎 Jenis: SSH brute-force
🌐 IP: 192.168.1.100
✅ Rekomendasi: Block IP temporer, aktifkan fail2ban
