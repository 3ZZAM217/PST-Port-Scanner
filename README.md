# 🛡️ PST (Port Scan Tool)

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

A high-performance, asynchronous TCP port scanner framework written in Python. Designed for speed, reliability, and modularity, it features a mini vulnerability engine and professional HTML reporting.

## 🚀 ProLevel Features
- **Asynchronous I/O:** Scans thousands of ports in seconds using `asyncio` without threading overhead.
- **Host Discovery:** Built-in ICMP ping sweep to ensure the target is online before scanning.
- **Advanced Fingerprinting:** Actively sends service-specific payloads to trick silent services into revealing their versions.
- **Vulnerability Engine:** A "mini-metasploit" that actively checks open ports for vulnerabilities (e.g., exposed `.env` files, dangerous HTTP methods, Anonymous FTP).
- **Beautiful Reporting:** Exports results cleanly to JSON, CSV, and stylized HTML reports.

---

## 📦 Installation

To run the source code, you must have Python 3.9+ installed.

1. **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## 🛠️ Usage
First, open your terminal and navigate to the folder where you downloaded or cloned the project:

Use the extremely convenient `pst` batch shortcut from your terminal!

```bash
# Basic Scan
.\pst 127.0.0.1

# The Ultimate Scan: Ping Sweep, Vulnerability Checks, and HTML Reporting
.\pst 127.0.0.1 -p 1-1000 --ping --vulns -f html -e report.html
```

### Full Options:
* `-p, --ports`: Specify ports (e.g., `80`, `1-1000`, `80,443`)
* `-t, --timeout`: Set connection timeout
* `-c, --concurrency`: Limit concurrent connections
* `--ping`: Enable ICMP host discovery
* `--vulns`: Enable the active vulnerability engine
* `-e, --export`: Specify a file to export results to
* `-f, --format`: Choose export format (`json`, `csv`, `html`)
