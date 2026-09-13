---

## 🔬 Part 1: The Manual Triage Methodology (SOC Tier-1 Deep Dive)

Before writing defensive automation, an analyst must understand the manual forensic methodology used to evaluate a suspicious artifact.

Below is the forensic examination of our simulated multi-vector phishing sample captured in an isolated environment.

---

### Step 1: Visual Inspection & Psychological Vectors

![Mailpit Rendered Email]<img width="1379" height="823" alt="Screenshot 2026-09-13 222653" src="https://github.com/user-attachments/assets/8345634c-1812-4d43-bfe4-982a85ec3928" />


#### Visual Indicators & Forensic Breakdown:
1. **Brand Impersonation:** The message clones **Microsoft Defender for Office 365** branding, using Microsoft's signature blue palette  clean Segoe UI typography, and official quarantine card formatting.
2. **Artificial Urgency (Fear & Urgency Lure):** The red alert banner explicitly claims:
   > *"Urgent: Inbound messages failed SPF/DMARC alignment... these communications will be purged within 24 hours."*
   This tactic induces panic, urging corporate personnel to bypass standard verification protocols.
3. **Apparent Authenticity:** The sender display name is explicitly set to `Microsoft 365 Defender`, giving the impression of an automated system notification.

---

### Step 2: Envelope & Transport Header Inspection

Examining the header metadata reveals fundamental inconsistencies between sender identity and response routing:

```email
From:     Microsoft 365 Defender <quarantine-admin@micros0ft.com>
To:       <soc-analyst@corp-internal.lab>
Reply-To: <harvest-gateway@attacker-infrastructure.xyz>
Subject:  ACTION REQUIRED: 3 Messages Quarantined - Release Documents Attached
---
### Step Forensic Findings:

Leet-speak Typosquatting (Visual Homoglyph):

Displayed Domain: micros0ft.com

Legitimate Domain: microsoft.com

The attacker swapped the vowel o with the numeric digit 0. To a cursory glance, this looks legitimate, but it resolves to an entirely different attacker-controlled domain.

Routing / Reply-To Mismatch:

The From: header claims to be Microsoft (micros0ft.com).

The Reply-To: destination points to attacker-infrastructure.xyz.

Analyst Conclusion: If an employee replies to inquire about legitimacy, the response routes directly to the attacker's harvesting gateway, completely bypassing corporate mail servers.

High-Risk Top-Level Domain (TLD):

The response address uses the .xyz TLD, a cheap registrar frequently abused for disposable Command-and-Control (C2) operations.
```

### Step 3: Body Code Audit & Visual Link Spoofing (Anchor Deception)

![Mailpit HTML Source]<img width="1149" height="710" alt="Screenshot 2026-09-13 222825" src="https://github.com/user-attachments/assets/96439e8b-5240-45f2-ade6-5a2bcd7567a6" />




An experienced analyst never clicks hyperlinks directly. Instead, inspecting the HTML source code reveals how the attacker visually tricks the victim:

```html
<!-- Attack Vector: HTML Visual Mismatch -->
<p>You can also authenticate directly using the web portal:</p>
<p style="text-align: center;">
  <a class="btn" href="[http://192.168.1.188/quarantine/review?auth=bypass](http://192.168.1.188/quarantine/review?auth=bypass)">Access Microsoft Quarantine Center</a>
</p>
<p style="font-size: 12px; text-align: center;">
  Or go to: <a href="[http://192.168.1.188/quarantine/review](http://192.168.1.188/quarantine/review)">[https://security.microsoft.com/quarantine](https://security.microsoft.com/quarantine)</a>
</p>
```
---

---

### Step 4: Manual Attachment Forensics & Cryptographic Evidence Acquisition

<img width="787" height="335" alt="Screenshot 2026-09-13 222710" src="https://github.com/user-attachments/assets/2884f02d-6712-4355-a9fe-a2329bd25744" />

*(Screenshot 2: Mailpit attachment container displaying incoming suspicious files)*

When an email contains attachments, a Tier-1 SOC analyst must treat them as potential remote code execution (RCE) or credential theft payloads. **Never double-click or launch suspicious attachments on an endpoint.**

The incoming email delivers two files:
1. `Quarantine_Report_Release_Notice.pdf.exe`
2. `Encrypted_SecureMessage_Portal.html`

---

#### 1. Forensic Inspection of File Naming & Threat Mechanics

* **File 1: `Quarantine_Report_Release_Notice.pdf.exe` (Double Extension Attack):**
  * **The Tactic:** Windows and macOS desktop environments frequently hide known file extensions by default (e.g., hiding `.exe`).
  * **The Deception:** The operating system displays the filename as `Quarantine_Report_Release_Notice.pdf` with an Adobe Acrobat or PDF viewer icon.
  * **The Reality:** The true file extension is `.exe` (Portable Executable binary). When clicked, the OS executes binary machine code rather than opening a document.

* **File 2: `Encrypted_SecureMessage_Portal.html` (HTML Smuggling):**
  * **The Tactic:** Attackers attach local web markup instead of linking to an external website.
  * **The Deception:** Email gateways often scan URLs for reputation, but benign `.html` files may pass through perimeter content filters.
  * **The Reality:** When opened, the browser executes the HTML/JavaScript locally in an isolated DOM context. It renders a fake login form that posts credentials back to an external attacker-controlled IP or C2 server.

---

---

## 🕵️‍♂️ Part 2: Tier-2 Deep-Dive Forensic Investigation

When standard initial checks flag suspicious indicators (e.g., typosquatting, raw IP links, or script attachments), an analyst does not stop at surface observations. The email is escalated to **Deep-Dive Forensics** to uncover attacker infrastructure, extract embedded scripts, and analyze behavioral intent.

---

### Step 1: Infrastructure & DNS WHOIS Attribution

Attackers often register lookalike domains using bulletproof hosters or free privacy proxies hours before launching a campaign. The analyst investigates domain ownership and DNS records directly via the terminal:

```bash
# 1. Check Domain Creation Date & Registrar (WHOIS)
whois micros0ft.com | grep -E -i "Creation Date|Registrar:|Registry Expiry"

# 2. Query Authoritative Mail & Identity Records (DNS)
dig micros0ft.com MX +short
dig micros0ft.com TXT +short

Case 1: When the Commands Give Output
What the Terminal Shows:
Plaintext
❯ whois micros0ft.com | grep -E -i "Creation Date|Registrar:|Registry Expiry"
   Creation Date: 2026-09-10T14:22:18Z
   Registrar: NameCheap, Inc.
   Registry Expiry Date: 2027-09-10T14:22:18Z

❯ dig micros0ft.com MX +short
10 mail.disposable-vps-hosting.net.

❯ dig micros0ft.com TXT +short
"v=spf1 ip4:192.168.1.188 +all"

Case 2: When the Commands Give NO Output (Blank Return)
What the Terminal Shows:

❯ whois micros0ft.com | grep -E -i "Creation Date|Registrar:|Registry Expiry"
No match for domain "MICROS0FT.COM".

❯ dig micros0ft.com MX +short
❯ 
❯ dig micros0ft.com TXT +short
❯
