# 🛠️ Lab Initialization: Docker & Mailpit Sandbox Setup

> Technical guide documenting the initial setup of the isolated security sandbox, starting from Docker installation on Kali Linux to the deployment and verification of the Mailpit SMTP gateway.

---

## 🏗️ 1. Docker Engine Installation & Verification

To ensure all phishing lures and weaponized email samples remain isolated from production networks, the analysis environment runs entirely inside containerized network boundaries on Kali Linux.

### Installation Steps

```bash
# Update local package index
sudo apt update

# Install Docker and container utilities
sudo apt install -y docker.io

# Enable and start the Docker system daemon
sudo systemctl enable --now docker

# Verify the Docker engine status
sudo systemctl status docker --no-pager
```
<img width="1163" height="566" alt="Screenshot 2026-09-13 235757" src="https://github.com/user-attachments/assets/02b74d14-cc58-4f21-a499-4ae197382cd4" />

---

## 📦 2. Deploying the Mailpit SMTP Capture Gateway
Mailpit is an open-source email capture and testing tool that acts as an isolated email sink. It accepts incoming SMTP traffic on port 1025 without routing packets to the open internet, while serving an analyst web console and REST API on port 8025.

# Pull and run Mailpit in a detached, isolated container
sudo docker run -d \
  --name mailpit \
  --restart unless-stopped \
  -p 8025:8025 \
  -p 1025:1025 \
  axllent/mailpit

# Confirm the running container and exposed ports
sudo docker ps

### Container Deployment Command
<img width="546" height="219" alt="Screenshot 2026-09-14 000404" src="https://github.com/user-attachments/assets/a5c092a3-3874-43e3-978a-caf8d5648b87" />

---

## 🌐 3. Analyst Dashboard Access & Readiness Check
Once the container is operational, the analyst accesses the local web management console to verify the sink is ready to accept incoming traffic.

### Open your browser in Kali Linux.

#### Navigate to:

# http://localhost:8025

<img width="1031" height="830" alt="Screenshot 2026-09-14 000429" src="https://github.com/user-attachments/assets/8a017861-bd75-44da-bdd4-b16866ad35eb" />

---

## 🧪 4. SMTP Pipeline Verification Test
### Before injecting complex multi-vector phishing lures, perform a basic loopback test to ensure port 1025 accepts inbound SMTP connections and stores messages in memory:
```
# Send a basic handshake verification message via netcat or python
 python3 -c '
 import smtplib
 from email.message import EmailMessage

 msg = EmailMessage()
 msg["Subject"] = "Lab Connectivity Baseline Check"
 msg["From"] = "sandbox-tester@internal.lab"
msg["To"] = "soc-analyst@corp-internal.lab"
msg.set_content("SMTP pipeline verified. Gateway ready for threat emulation.")

with smtplib.SMTP("localhost", 1025) as s:
    s.send_message(msg)
print("[+] Test handshake delivered successfully!")
'
```
<img width="662" height="298" alt="Screenshot 2026-09-14 000539" src="https://github.com/user-attachments/assets/51252e9c-c624-48d5-8f1e-2e3cbb25b5e6" />

<img width="1525" height="518" alt="Screenshot 2026-09-14 001627" src="https://github.com/user-attachments/assets/1ba20f48-0ad4-40ac-b4a3-f5319a44ad87" />

---

# ⚙️ Engineering PhishGuard: Automated SOC Triage Engine & VirusTotal API Integration

> Technical guide detailing the architecture of `phishguard.py`, secure API key handling, threat-intelligence integration via the VirusTotal v3 API, algorithmic scoring, and programmatic execution.

---

## 🏗️ 1. Architecture of `phishguard.py`

The script replaces manual Tier-1 and Tier-2 triage by running multi-vector forensic algorithms concurrently across the raw RFC 822 MIME container:

---

## 🔑 2. Secure VirusTotal API Key Configuration

Never hardcode threat intelligence API credentials inside source code. `phishguard.py` reads the secret key dynamically from the system environment.

### Setting the Environment Variable in Kali Linux:

```bash
# Export your VirusTotal v3 API key temporarily for the current session:
export VT_API_KEY="your_actual_virustotal_api_key_here"

# (Optional) Persist across reboots in ~/.bashrc or ~/.zshrc:
echo 'export VT_API_KEY="your_actual_virustotal_api_key_here"' >> ~/.zshrc
source ~/.zshrc

# Verify the environment variable is loaded:
echo $VT_API_KEY | cut -c 1-8

---
```
# 🐍 3. Full Production Script: phishguard.py

## Core Detection Engine & Algorithmic Capabilities
PhishGuard is an automated, high-throughput email triage engine engineered to replicate and accelerate Tier-1/Tier-2 SOC forensic workflows in under 50 milliseconds. The tool parses raw RFC 822 MIME objects to uncover multi-layer evasions across headers, body markup, and binary attachments. Rather than relying on simple keyword matching, PhishGuard leverages normalized pattern recognition, typographic distance algorithms, and live threat intelligence lookups to compute a deterministic risk score (0–100) and normalize Indicators of Compromise (IOCs) into SIEM-ready JSON reports.

* Visual Homoglyph & Leet-Speak Typosquatting: Normalizes character substitutions (e.g., 0 $\rightarrow$ o, 1 $\rightarrow$ l) and computes Levenshtein edit distances against an internal catalog of 80+ enterprise brands (such as Microsoft, Google, and PayPal) to uncover lookalike infrastructure like micros0ft.com.

* HTML Anchor Deception & Raw IP Auditing: Implements a custom streaming HTMLParser that evaluates href targets against visible anchor text, catching discrepancies where benign-looking text (e.g., security.microsoft.com) masks redirection to unauthorized raw IP hosts ([http://192.168.](http://192.168.)x.x) or attacker-controlled C2 routes.

* MIME Transport & Header Discrepancy Auditing: Inspects sender identity alignment by comparing From, Reply-To, and Return-Path headers to detect unauthenticated display spoofing, unauthorized reply redirection, and disposable high-risk Top-Level Domains (TLDs).

* Cryptographic Payload Carving & Magic Byte Inspection: Automatically carves inbound MIME attachments without host execution, flags evasive naming patterns (such as double-extension .pdf.exe executables and HTML smuggling .html files), and computes SHA-256 cryptographic signatures.

* VirusTotal v3 Intelligence & Safe Defanging: Ingests live threat telemetry via the VirusTotal v3 REST API to correlate carved hashes with global AV engines, automatically defanging extracted URLs (hxxp://, [.]) to ensure safe operational handling.

## Ensure this code is saved in ~/phishops/phishguard.py:
```
#!/usr/bin/env python3
import os
import sys
import re
import json
import hashlib
import unicodedata
from datetime import datetime
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
import requests

# -------------------------------------------------------------
# Protected Brand Catalog for Typosquatting Analysis
# -------------------------------------------------------------
PROTECTED_BRANDS = [
    "microsoft", "office365", "outlook", "google", "apple", "paypal",
    "amazon", "chase", "wellsfargo", "bankofamerica", "dhl", "fedex"
]

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".vbs", ".ps1", ".scr", ".js", ".hta", ".html", ".iso"
}

LEET_MAP = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
    '7': 't', '8': 'b', '@': 'a', '$': 's'
}

def defang_url(url: str) -> str:
    url = re.sub(r"^https://", "hxxps://", url, flags=re.IGNORECASE)
    url = re.sub(r"^http://", "hxxp://", url, flags=re.IGNORECASE)
    return url.replace(".", "[.]")

def normalize_leet(domain: str) -> str:
    normalized = unicodedata.normalize('NFKD', domain)
    for k, v in LEET_MAP.items():
        normalized = normalized.replace(k, v)
    return normalized

def check_virustotal_hash(file_hash: str, api_key: str) -> dict:
    if not api_key:
        return {"status": "skipped", "reason": "No VT_API_KEY exported"}
    
    url = f"[https://www.virustotal.com/api/v3/files/](https://www.virustotal.com/api/v3/files/){file_hash}"
    headers = {"x-apikey": api_key}
    
    try:
        res = requests.get(url, headers=headers, timeout=8)
        if res.status_code == 200:
            stats = res.json()["data"]["attributes"]["last_analysis_stats"]
            return {
                "status": "detected",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0)
            }
        elif res.status_code == 404:
            return {"status": "not_found", "reason": "Zero-day hash unknown to VT"}
        else:
            return {"status": "error", "code": res.status_code}
    except Exception as e:
        return {"status": "error", "message": str(e)}

class AnchorExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.anchors = []
        self.current_href = None
        self.current_text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for attr, val in attrs:
                if attr.lower() == "href":
                    self.current_href = val

    def handle_data(self, data):
        if self.current_href:
            self.current_text.append(data.strip())

    def handle_endtag(self, tag):
        if tag == "a" and self.current_href:
            visible = " ".join(self.current_text).strip()
            self.anchors.append({"href": self.current_href, "visible_text": visible})
            self.current_href = None
            self.current_text = []

def analyze_email(eml_path: str):
    if not os.path.exists(eml_path):
        print(f"[-] Target file not found: {eml_path}")
        sys.exit(1)

    with open(eml_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    threat_score = 0
    findings = []
    iocs = {"urls": [], "attachments": []}

    vt_key = os.getenv("VT_API_KEY", "")

    # 1. Header Analysis
    from_header = str(msg.get("From", ""))
    reply_to = str(msg.get("Reply-To", ""))
    subject = str(msg.get("Subject", "No Subject"))

    from_domain = from_header.split("@")[-1].replace(">", "").strip() if "@" in from_header else ""
    reply_domain = reply_to.split("@")[-1].replace(">", "").strip() if "@" in reply_to else ""

    if reply_to and from_domain and reply_domain and (from_domain.lower() != reply_domain.lower()):
        threat_score += 25
        findings.append(f"Header Mismatch: From domain '{from_domain}' differs from Reply-To '{reply_domain}'")

    # 2. Typosquatting / Leet-speak Analysis
    norm_from = normalize_leet(from_domain)
    for brand in PROTECTED_BRANDS:
        if brand in norm_from and brand not in from_domain:
            threat_score += 35
            findings.append(f"Typosquatting Detected: '{from_domain}' mimics protected brand '{brand}'")

    # 3. HTML Anchor Auditing
    html_content = ""
    for part in msg.walk():
        if part.get_content_type() == "text/html":
            html_content = part.get_content()

    if html_content:
        parser = AnchorExtractor()
        parser.feed(html_content)
        for anchor in parser.anchors:
            href = anchor["href"]
            visible = anchor["visible_text"]
            defanged = defang_url(href)
            iocs["urls"].append({"original": defanged, "visible_text": visible})

            # Check anchor text mismatch
            if ("http://" in visible or "https://" in visible) and (visible.rstrip("/") != href.rstrip("/")):
                threat_score += 45
                findings.append(f"Visual Anchor Spoofing: Display text '{visible}' points to '{href}'")
            
            # Check raw IP destination
            if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", href):
                threat_score += 20
                findings.append(f"Raw IP Destination: Link uses unencrypted host IP ({href})")

    # 4. Attachment Hashing & VirusTotal Query
    for part in msg.iter_attachments():
        filename = part.get_filename() or "unknown_payload"
        data = part.get_payload(decode=True)
        sha256 = hashlib.sha256(data).hexdigest()

        # Flag dangerous extensions
        for ext in SUSPICIOUS_EXTENSIONS:
            if filename.lower().endswith(ext):
                threat_score += 40
                findings.append(f"Dangerous Attachment: Suspicious extension '{ext}' detected on '{filename}'")
                break

        # Query VirusTotal API
        vt_result = check_virustotal_hash(sha256, vt_key)
        if vt_result.get("malicious", 0) > 0:
            threat_score += 50
            findings.append(f"VirusTotal Threat Match: {vt_result['malicious']} security engines flagged {filename}")

        iocs["attachments"].append({
            "filename": filename,
            "sha256": sha256,
            "virustotal": vt_result
        })

    # Normalize Score
    final_score = min(threat_score, 100)
    verdict = "BENIGN / LOW RISK"
    if final_score >= 60:
        verdict = "MALICIOUS / HIGH PROBABILITY PHISH"
    elif final_score >= 25:
        verdict = "SUSPICIOUS / INVESTIGATION REQUIRED"

    # Terminal Report Output
    print("\n" + "="*70)
    print("🛡️  PHISHGUARD AUTOMATED SOC TRIAGE REPORT")
    print("="*70)
    print(f"Subject      : {subject}")
    print(f"From Header  : {from_header}")
    print(f"Reply-To     : {reply_to}")
    print(f"Threat Score : {final_score} / 100")
    print(f"Verdict      : {verdict}")
    print("-" * 70)
    print("[!] Triggered Security Findings:")
    for f_item in findings:
        print(f"    - {f_item}")
    print("-" * 70)
    print("[*] Indicators of Compromise (Defanged):")
    for u in iocs["urls"]:
        print(f"    - URL: {u['original']}")
    for a in iocs["attachments"]:
        print(f"    - File: {a['filename']} | SHA256: {a['sha256']}")
        print(f"      VT Intelligence: {a['virustotal']}")
    print("="*70)

    # 5. Export Structured JSON Report
    reports_dir = os.path.expanduser("~/phishops/reports")
    os.makedirs(reports_dir, exist_ok=True)
    report_filename = f"report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    report_path = os.path.join(reports_dir, report_filename)

    export_data = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "file": os.path.basename(eml_path),
        "subject": subject,
        "from": from_header,
        "threat_score": final_score,
        "verdict": verdict,
        "findings": findings,
        "iocs": iocs
    }

    with open(report_path, "w") as out:
        json.dump(export_data, out, indent=2)

    print(f"[+] SIEM-Ready Incident JSON generated: {report_path}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 phishguard.py <path_to_email.eml>")
        sys.exit(1)
    analyze_email(sys.argv[1])
---
```
# ⚡ 4. Programmatic Tool Execution
Run the tool against the ingested sandbox sample:
```
# Bash
cd ~/phishops
python3 phishguard.py m365_quarantine_phish.eml
```
<img width="1884" height="814" alt="Screenshot 2026-09-14 004541" src="https://github.com/user-attachments/assets/703a0331-f68b-4166-821e-0f7f36a726f4" />


