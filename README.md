# Matrix-Scanner
Matrix Scanner | iRC-PT v9.0 Pro

<h1 align="center">🧠 iRC-PT Matrix Scanner v9.0 Pro</h1>
<p align="center">
  <img src="https://img.shields.io/badge/version-9.0-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/status-stable-brightgreen?style=flat-square" />
  <img src="https://img.shields.io/badge/python-3.9+-yellow?style=flat-square" />
  <img src="https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square" />
</p>

> ⚡ Advanced network scanning and reconnaissance tool for professional assessments  
> 👥 Developed by: **Iranian Cyber Phantom Team (iRC-PT)**  
> 💬 Telegram Support: [@Iranian_Cybers](https://t.me/Iranian_Cybers)

---

## 🚀 Features

- 🎯 Multi-threaded TCP/UDP port scanning (quick, normal, full)
- 🔎 Banner grabbing & service version detection
- 🛡️ Web Application Firewall (WAF) identification
- 🧠 OS & device fingerprinting (router, webcam, NAS, etc.)
- 🌍 GeoIP lookup (city, country, coordinates)
- 🌐 DNS record analysis (A, MX, TXT, NS, CNAME)
- 🧩 Vulnerability hints via internal CVE database
- 🪤 Honeypot detection logic (kippo, cowrie, etc.)
- 📝 Output: `.json`, `.txt`, `.csv`, `.html`, `.xml`, `.pdf`
- 📅 Built-in scheduler for recurring scans
- 🌐 RESTful API mode via Flask
- 🧷 Proxy support (SOCKS5 / HTTP)

---

## ⚙️ Installation

```bash
git clone https://github.com/PrivateiRC/Matrix-Scanner/
cd Matrix-Scanner
pip install -r requirements.txt

> ℹ️ Optional: For GeoIP features, download and place GeoLite2-City.mmdb in the root folder:
https://dev.maxmind.com/geoip/geolite2/




---

🧪 Quick Start

CLI

python3 main2.py scan example.com full --threads 300 --output results.json

API

python3 main2.py --api

Then send POST requests to:

POST http://localhost:5000/api/scan

Payload:

{
  "target": "example.com",
  "scan_type": "quick",
  "threads": 150
}


---

📤 Output Formats

Format	Description

.json	Machine-readable structured data
.txt	Plain text log
.csv	Table format
.html	Clean Bootstrap-based web report
.xml	Structured markup format
.pdf	Printable professional report



---

💡 Example Commands

Command	Description

scan target.com quick 200	Fast scan using 200 threads
save report.json	Save latest results as JSON
report report.pdf	Generate a printable PDF
proxy socks5 127.0.0.1 9050	Route via SOCKS5 proxy
schedule target.com 24 results.html	Daily scan & report
services	Show known ports/services
exit	Exit the tool
help	View available commands



---

📬 Contact

For technical support or feature requests:
📨 Telegram: @Iranian_Cybers


---

📜 License

Licensed under the MIT License.
Use only in legal, ethical, and authorized environments.


---

⭐️ Support the Project

If you find this project useful, please consider giving it a ⭐ on GitHub!

---
