🛡️ GLAR-EVIT
Google Workspace Log Analysis & Evidence Validation Investigation Tool

Version 9.0 – Enterprise Forensic Edition

📌 What is GLAR-EVIT?

GLAR-EVIT is a CLI-based digital forensics and investigation tool designed for Google Workspace environments.
It helps security teams, blue-team engineers, and auditors collect, analyze, and preserve Google Workspace logs in a forensically sound manner.

This tool is built for:

Incident Response (IR)

Insider Threat Investigations

Compliance & Audit Reviews

Security Operations (SOC)

Legal & Evidence Preservation workflows

⚠️ Important: GLAR-EVIT uses read-only Google Workspace APIs and does not modify any data.

🚀 Key Capabilities
🔐 1. Administrator Authentication

Admin email verification

Secure OAuth 2.0 authentication (Google-recommended)

Token auto-refresh

Domain validation

No hardcoded credentials

Password-based API authentication is not supported by Google. OAuth is the only compliant method.

👤 2. Target User Investigation

Input any existing employee email

Automatic domain detection

Validation before log collection

Single-user, case-based investigation model

⏱️ 3. Time Range Selection

Choose how far back the investigation should go:

Last 90 Days – recent activity

Last 120 Days – extended review

All Available Logs – full historical scope (API-limited)

📂 Log Types Collected (7 Categories)
#	Log Type	Description
1	Drive File Downloads	Files downloaded from Google Drive
2	Drive Shared Externally	Files shared outside the organization
3	Deleted Emails	Messages moved to trash or deleted
4	Attachment Downloads	Email attachments downloaded
5	Emails Sent Externally	Emails sent outside the domain
6	Chrome Logs	Chrome browser activity logs
7	Device Logs	Endpoint / device activity logs

All logs are pulled directly from Google Workspace Admin Reports APIs.

📤 Export Options

GLAR-EVIT allows exporting logs in:

Excel (.xlsx) – recommended for investigations

Structured tables

Analyst-friendly

CSV (.csv) – UTF-8 encoded

SIEM-ready

Script-friendly

🔍 Forensic Integrity & Evidence Handling

GLAR-EVIT is designed with forensic best practices:

✅ SHA-256 hashing for every output file

✅ Automatic forensic manifest (FORENSIC_MANIFEST.json)

✅ Case-based directory structure

✅ Timestamp normalization (UTC)

✅ Chain-of-custody friendly output

🧩 Installation Guide
✅ Prerequisites

Python 3.8+

Google Workspace Admin access

Google Cloud Project

OAuth credentials (credentials.json)

📦 Step 1: Install Dependencies
pip install -r requirements.txt

☁️ Step 2: Google Cloud Configuration

Go to Google Cloud Console
👉 https://console.cloud.google.com/

Create or select a project

Enable APIs:

Admin SDK API

Google Workspace Audit API

Create OAuth Credentials:

APIs & Services → Credentials

Create Credentials → OAuth Client ID

Application type: Desktop App

Download the JSON file

Rename it to:

credentials.json


Place it in the GLAR-EVIT directory

🔑 Step 3: Domain-Wide Delegation (Recommended)

In Google Workspace Admin Console:

Security → API Controls → Domain-wide Delegation

Add new delegation

Client ID: (from OAuth credentials)

Scopes:

https://www.googleapis.com/auth/admin.reports.audit.readonly
https://www.googleapis.com/auth/admin.reports.usage.readonly

▶️ How to Run GLAR-EVIT
python GLAR_EViT_v9.py

🧭 Typical Investigation Flow
STEP 1: Admin Authentication
STEP 2: Target Employee Selection
STEP 3: Time Range Selection
STEP 4: Export Format Selection
STEP 5: Log Extraction & Processing
STEP 6: Evidence Validation & Manifest Creation


The tool guides you step-by-step with clear prompts and progress indicators.

📁 Output Structure
GLAR_CASES/
└── GLAR_CASE_<username>_<timestamp>/
    ├── Emails_Sent_Externally.xlsx
    ├── Deleted_Mails.xlsx
    ├── Attachment_Downloads.xlsx
    ├── Drive_Shared_Externally.xlsx
    ├── Drive_File_Downloads.xlsx
    ├── Chrome_Logs.xlsx
    ├── Device_Logs.xlsx
    └── FORENSIC_MANIFEST.json


Each case is isolated, timestamped, and verifiable.

🧾 Log Field Coverage (Summary)
✉️ Email-Based Logs

Message ID

Subject

Sender / Recipient (Header & Envelope)

Attachments (name, hash, malware family*)

Confidential Mode flag*

Source IP

Client & device identifiers*

* Available only if exposed by Google APIs.

📁 Drive Logs

Document ID & title

File type

Ownership

Visibility changes

External sharing events

Source IP

Encryption status

🌐 Chrome & Device Logs

Full event coverage

All available parameters dynamically extracted

Raw parameters preserved for deep analysis

⚙️ Technical Highlights
🚀 Performance

Multi-threaded fetching (concurrent execution)

Progress bars using tqdm

Optimized pagination handling

🔁 Reliability

Exponential backoff

Automatic retry on:

429 (Rate limit)

500 / 503 (Server errors)

🔐 Security

OAuth 2.0 authentication

Token auto-refresh

No plaintext credentials

Domain-restricted execution

⚖️ Legal & Compliance Notice

GLAR-EVIT is intended only for authorized investigations.
Ensure usage complies with:

Organizational security policies

Local laws and regulations

Employee privacy requirements

Unauthorized use may be illegal.

👨‍💻 Author

Vishnu Manikandan
Security Researcher | Blue Team | Forensics & IR

⭐ Final Note

If you find GLAR-EVIT useful:

⭐ Star the repository

🐞 Report issues

🔧 Contribute improvements

This project is built to help defenders investigate with confidence.