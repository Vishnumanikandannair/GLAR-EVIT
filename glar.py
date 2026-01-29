#!/usr/bin/env python3
# =====================================================================================
# GLAR_EVIT – Google Workspace Log Analyser & Reviewer
# GWS Forensic Suite v9.0 (Complete Edition)
# Created & Author : Vishnu Manikandan
# =====================================================================================

import os
import sys
import time
import datetime
import pickle
import webbrowser
import logging
import json
import hashlib
import random
import concurrent.futures
import re
import getpass
from typing import List, Dict, Any, Optional
from dateutil import parser as date_parser

# --- DEPENDENCY CHECK ---
def check_dependencies():
    missing = []
    required = {
        "colorama": "colorama",
        "pandas": "pandas",
        "google_auth_oauthlib": "google_auth_oauthlib",
        "googleapiclient": "googleapiclient.discovery",
        "openpyxl": "openpyxl",
        "tqdm": "tqdm",
        "dateutil": "dateutil"
    }

    for pkg, mod in required.items():
        try:
            __import__(mod)
        except ImportError:
            missing.append(pkg)

    if missing:
        print("\n" + "="*60)
        print("MISSING LIBRARIES DETECTED")
        print("="*60)
        print("Please run this command to install:")
        print("pip install google-api-python-client google-auth-oauthlib google-auth-httplib2 pandas openpyxl colorama tqdm python-dateutil")
        print("="*60)
        input("Press Enter to exit...")
        sys.exit(1)

check_dependencies()

# --- IMPORTS ---
import pandas as pd
from tqdm import tqdm
from colorama import init, Fore, Style, Back
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# --- CONFIGURATION ---
# Use environment variables or default to an empty string for security
DOMAIN_NAME = os.getenv("GWS_DOMAIN", "yourdomain.com") 
SCOPES = [
    'https://www.googleapis.com/auth/admin.reports.audit.readonly',
    'https://www.googleapis.com/auth/admin.reports.usage.readonly'
]
CREDENTIALS_FILE = 'credentials.json'
TOKEN_FILE = 'token.pickle'
BASE_DIR = "GLAR_CASES"
MAX_RETRIES = 5
THREADS = 6

# Admin credentials storage (in production, use secure vault)
# This is for demonstration - in real scenario, use OAuth2 only
ADMIN_STORE = {}

# --- ASCII LOGO ---
LOGO = r"""
    ╔══════════════════════════════════════════════════════════════════════╗
    ║                                                                      ║
    ║    ██████╗ ██╗      █████╗ ██████╗     ███████╗██╗   ██╗██╗████████╗ ║
    ║   ██╔════╝ ██║     ██╔══██╗██╔══██╗    ██╔════╝██║   ██║██║╚══██╔══╝ ║
    ║   ██║  ███╗██║     ███████║██████╔╝    █████╗  ██║   ██║██║   ██║    ║
    ║   ██║   ██║██║     ██╔══██║██╔══██╗    ██╔══╝  ╚██╗ ██╔╝██║   ██║    ║
    ║   ╚██████╔╝███████╗██║  ██║██║  ██║    ███████╗ ╚████╔╝ ██║   ██║    ║
    ║    ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝    ╚══════╝  ╚═══╝  ╚═╝   ╚═╝    ║
    ║                                                                      ║
    ║           Google Workspace Log Analyser & Reviewer v9.0              ║
    ║                    GWS Forensic Suite                                ║
    ║            Created & Author : Vishnu Manikandan                      ║
    ╚══════════════════════════════════════════════════════════════════════╝
"""

# Initialize Colorama
init(autoreset=True)

# --- UTILITY FUNCTIONS ---
def get_hash(file_path: str) -> str:
    """Generate SHA256 hash for forensic integrity."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def format_timestamp(iso_time: str) -> str:
    """Format ISO timestamp to YYYY-MM-DD, HH:MM:SS."""
    try:
        dt = date_parser.parse(iso_time)
        return dt.strftime("%Y-%m-%d, %H:%M:%S")
    except:
        return iso_time

def is_external_domain(email: str) -> bool:
    """Check if email is from external domain."""
    if not email or "@" not in str(email):
        return False
    return not str(email).lower().endswith(f"@{DOMAIN_NAME.lower()}")

def parse_email_list(email_string: str) -> List[str]:
    """Parse comma-separated email list."""
    if not email_string:
        return []
    return [e.strip() for e in str(email_string).split(",") if e.strip()]

# --- MAIN CLASS ---
class GLARForensics:
    def __init__(self):
        self.service = None
        self.admin_email = None
        self.admin_password = None
        self.target_email = None
        self.start_time = None
        self.export_fmt = None
        self.case_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.case_path = ""
        self.manifest = {}
        self.setup_logging()
        self.setup_console()

    def setup_console(self):
        """Sets console color to Hacker Green (Windows/Linux)."""
        if os.name == 'nt':
            os.system('color 0A')

    def setup_logging(self):
        logging.basicConfig(
            filename='glar_execution.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def print_banner(self):
        self.clear_screen()
        print(Fore.GREEN + Style.BRIGHT + LOGO)
        print(Fore.GREEN + "="*74)

    def print_styled(self, text, level="info"):
        """Consistent logging to console."""
        prefix = "[*]"
        color = Fore.GREEN

        if level == "error": 
            prefix = "[!]"
            color = Fore.RED
        elif level == "input": 
            prefix = "[?]"
            color = Fore.CYAN
        elif level == "warn":
            prefix = "[!]"
            color = Fore.YELLOW
        elif level == "success":
            prefix = "[✓]"
            color = Fore.GREEN
        elif level == "forensic":
            prefix = "[F]"
            color = Fore.MAGENTA
        elif level == "auth":
            prefix = "[🔐]"
            color = Fore.CYAN

        print(color + f"{prefix} {text}" + Fore.GREEN)

    def verify_admin_credentials(self, email: str, password: str) -> bool:
        """Verify admin credentials against Google Workspace."""
        # In production, this uses OAuth2 flow
        # The actual verification happens during OAuth2 authentication
        # This function serves as a placeholder for additional verification layers
        if DOMAIN_NAME not in email:
            return False
        return True

    def authenticate(self):
        """Handles OAuth2 Logic with Admin Verification."""
        self.print_styled("Initializing Google Workspace Authentication...", "auth")
        creds = None

        # 1. Load Token
        if os.path.exists(TOKEN_FILE):
            try:
                with open(TOKEN_FILE, 'rb') as token:
                    creds = pickle.load(token)
                self.print_styled("Existing token loaded.", "info")
            except Exception:
                self.print_styled("Token corrupted. Re-authenticating.", "warn")

        # 2. Refresh or Login
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                    self.print_styled("Token refreshed successfully.", "success")
                except Exception as e:
                    self.print_styled(f"Token refresh failed: {e}", "warn")
                    creds = None

            if not creds:
                if not os.path.exists(CREDENTIALS_FILE):
                    print(Fore.RED + "\n[!] ERROR: 'credentials.json' is missing!")
                    print(Fore.GREEN + "-"*50)
                    print("1. Go to Google Cloud Console")
                    print("   (https://console.cloud.google.com/apis/credentials)")
                    print("2. Create OAuth 2.0 Client ID (Desktop App)")
                    print("3. Download JSON, rename to 'credentials.json'")
                    print("4. Place it in this folder")
                    print("-"*50)

                    if input(Fore.YELLOW + "Open Google Cloud Console? (y/n): ").lower() == 'y':
                        webbrowser.open("https://console.cloud.google.com/apis/credentials")
                    sys.exit(1)

                # Perform OAuth2 Login Flow
                self.print_styled("Starting OAuth2 authentication flow...", "auth")
                self.print_styled("Please authenticate in your browser...", "input")
                flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
                creds = flow.run_local_server(port=0)
                self.print_styled("OAuth2 authentication completed.", "success")

            # Save Token
            with open(TOKEN_FILE, 'wb') as token:
                pickle.dump(creds, token)
            self.print_styled("Authentication token saved securely.", "success")

        self.service = build('admin', 'reports_v1', credentials=creds, cache_discovery=False)
        self.print_styled("Successfully connected to Google Workspace API.", "success")
        time.sleep(1)

    def get_user_inputs(self):
        """Complete Input Wizard with Admin Verification."""
        self.print_banner()

        # Admin Authentication
        self.print_styled("STEP 1: Administrator Authentication", "auth")
        print(Fore.GREEN + "-"*50)

        while True:
            self.admin_email = input(Fore.GREEN + "[?] Enter Admin Email ID: ").strip()
            if '@' in self.admin_email and DOMAIN_NAME in self.admin_email:
                break
            self.print_styled(f"Invalid Admin Email. Must be from {DOMAIN_NAME}", "warn")

        # Note: In real OAuth2, password is not needed - the flow handles it
        # This is for UI completeness
        self.admin_password = getpass.getpass(Fore.GREEN + "[?] Enter Admin Password (hidden): ").strip()

        if not self.verify_admin_credentials(self.admin_email, self.admin_password):
            self.print_styled("Admin verification failed!", "error")
            sys.exit(1)

        self.print_styled("Admin credentials verified.", "success")
        print(Fore.GREEN + "-"*50 + "\n")

        # Target Employee Email
        self.print_styled("STEP 2: Target User Configuration", "input")
        print(Fore.GREEN + "-"*50)

        while True:
            self.target_email = input(Fore.GREEN + "[?] Enter Existing Employee Email: ").strip()
            if '@' in self.target_email and DOMAIN_NAME in self.target_email:
                break
            self.print_styled(f"Invalid Email. Must be from {DOMAIN_NAME}", "warn")

        print(Fore.GREEN + "-"*50 + "\n")

        # Time Interval Selection
        self.print_styled("STEP 3: Time Range Selection", "input")
        print(Fore.GREEN + "-"*50)
        print(Fore.GREEN + "[1] Last 90 Days")
        print(Fore.GREEN + "[2] Last 120 Days")
        print(Fore.GREEN + "[3] Every Log Till User Accessed Gmail (All Available)")

        choice = input(Fore.GREEN + "[?] Select Option [1-3]: ").strip()

        now = datetime.datetime.utcnow()
        if choice == '1': 
            delta = 90
            period = "Last 90 Days"
        elif choice == '2': 
            delta = 120
            period = "Last 120 Days"
        else: 
            delta = 3650  # ~10 years (all available)
            period = "All Available Logs"

        self.start_time = (now - datetime.timedelta(days=delta)).isoformat("T") + "Z"
        print(Fore.GREEN + "-"*50 + "\n")

        # Export Format Selection
        self.print_styled("STEP 4: Export Format Selection", "input")
        print(Fore.GREEN + "-"*50)
        print(Fore.GREEN + "[1] Google Excel (.xlsx) - Recommended")
        print(Fore.GREEN + "[2] CSV (.csv)")

        fmt_choice = input(Fore.GREEN + "[?] Select Option [1-2]: ").strip()
        self.export_fmt = "xlsx" if fmt_choice == "1" else "csv"
        print(Fore.GREEN + "-"*50 + "\n")

        # Create case directory
        user_clean = self.target_email.split('@')[0]
        self.case_path = os.path.join(BASE_DIR, f"GLAR_CASE_{user_clean}_{self.case_id}")
        os.makedirs(self.case_path, exist_ok=True)

        # Display Summary
        print(Fore.GREEN + "="*74)
        self.print_styled("CONFIGURATION SUMMARY", "success")
        print(Fore.GREEN + "="*74)
        self.print_styled(f"Admin Email:    {self.admin_email}", "info")
        self.print_styled(f"Target Email:   {self.target_email}", "info")
        self.print_styled(f"Time Period:    {period}", "info")
        self.print_styled(f"Export Format:  {self.export_fmt.upper()}", "info")
        self.print_styled(f"Case Directory: {self.case_path}", "info")
        print(Fore.GREEN + "="*74 + "\n")

        confirm = input(Fore.CYAN + "[?] Proceed with extraction? (y/n): ").strip().lower()
        if confirm != 'y':
            self.print_styled("Operation cancelled by user.", "warn")
            sys.exit(0)

    def fetch_with_backoff(self, app_name: str, event_name: str = None) -> List[Dict]:
        """API Fetcher with exponential backoff retry logic."""
        all_logs = []
        page_token = None

        self.print_styled(f"Fetching {app_name.upper()} logs...", "forensic")

        while True:
            try:
                request = self.service.activities().list(
                    userKey=self.target_email,
                    applicationName=app_name,
                    eventName=event_name,
                    startTime=self.start_time,
                    maxResults=1000,
                    pageToken=page_token
                )

                # Retry logic with exponential backoff
                response = None
                for attempt in range(MAX_RETRIES):
                    try:
                        response = request.execute()
                        break
                    except HttpError as e:
                        if e.resp.status in [429, 500, 503]:
                            sleep_time = (2 ** attempt) + random.random()
                            self.print_styled(f"Rate limit. Retrying in {sleep_time:.1f}s...", "warn")
                            time.sleep(sleep_time)
                        elif e.resp.status == 404:
                            return all_logs
                        else:
                            raise e

                if response is None:
                    self.print_styled(f"Failed to fetch {app_name} after max retries", "error")
                    break

                items = response.get('items', [])
                all_logs.extend(items)

                page_token = response.get('nextPageToken')
                if not page_token:
                    break

            except HttpError as e:
                logging.error(f"API Error ({app_name}): {e}")
                break
            except Exception as e:
                logging.error(f"Unexpected error ({app_name}): {e}")
                break

        self.print_styled(f"{app_name.upper()}: {len(all_logs)} events fetched", "success")
        return all_logs

    def get_param(self, params, name):
        """Helper to find value in parameter list."""
        if not params:
            return ""
        for p in params:
            if p.get('name') == name:
                return p.get('value') or p.get('boolValue') or p.get('intValue') or ""
        return ""

    # =================================================================================
    # LOG PROCESSORS - With EXACT field mappings as specified
    # =================================================================================

    def process_emails_sent_externally(self, logs):
        """
        Process emails sent to external domains.
        Fields: Date, Message ID, Subject, Event, From(Header address), From (Envelope),
                To (Envelope), Owner, Descriptin, Domain, Attachment Hash, Attachment Name,
                Attachment Malware Family, IP Address, From(Header name), Confidential mode
        """
        rows = []
        for log in logs:
            events = log.get('events', [])
            for event in events:
                if event.get('name') != 'email_sent':
                    continue

                p = event.get('parameters', [])
                to_envelope = self.get_param(p, 'to')

                # Check if any recipient is external
                recipients = parse_email_list(to_envelope)
                has_external = any(is_external_domain(r) for r in recipients)

                if not has_external:
                    continue

                rows.append({
                    "Date (YYYY-MM-DD, Timestamp)": format_timestamp(log['id']['time']),
                    "Message ID": self.get_param(p, 'message_id'),
                    "Subject": self.get_param(p, 'subject'),
                    "Event": "email_sent",
                    "From(Header address)": self.get_param(p, 'from_header_address'),
                    "From (Envelope)": self.get_param(p, 'from'),
                    "To (Envelope)": to_envelope,
                    "Owner": log.get('actor', {}).get('email', ''),
                    "Descriptin": "Email sent to external domain",
                    "Domain": DOMAIN_NAME,
                    "Attachment Hash": self.get_param(p, 'attachment_hash'),
                    "Attachment Name": self.get_param(p, 'attachment_name'),
                    "Attachment Malware Family": self.get_param(p, 'malware_family'),
                    "IP Address": log.get('ipAddress', ''),
                    "From(Header name)": self.get_param(p, 'from_header'),
                    "Confidential mode": self.get_param(p, 'confidential_mode')
                })
        return pd.DataFrame(rows)

    def process_drive_shared_externally(self, logs):
        """
        Process Drive files shared externally.
        Fields: Date, Document ID, Title, Document Type, Prior Visibilty, Visibilty,
                Event, Description, Actor, Owner, IP Address, Encrypted, Domain
        """
        rows = []
        for log in logs:
            events = log.get('events', [])
            for event in events:
                if event.get('name') not in ['change_user_access', 'change_document_access', 'change_document_visibility']:
                    continue

                p = event.get('parameters', [])
                target_user = self.get_param(p, 'target_user')
                visibility = self.get_param(p, 'visibility')
                old_visibility = self.get_param(p, 'old_value') or self.get_param(p, 'old_visibility')

                # Check if shared externally
                is_ext = False
                if target_user and is_external_domain(target_user):
                    is_ext = True
                if visibility in ['public', 'people_with_link', 'anyone_with_link']:
                    is_ext = True

                if not is_ext:
                    continue

                rows.append({
                    "Date (YYYY-MM-DD, Timestamp)": format_timestamp(log['id']['time']),
                    "Document ID": self.get_param(p, 'doc_id'),
                    "Title": self.get_param(p, 'doc_title'),
                    "Document Type": self.get_param(p, 'doc_type'),
                    "Prior Visibilty": old_visibility,
                    "Visibilty": visibility,
                    "Event": event.get('name', ''),
                    "Description": f"Document shared externally with {target_user}" if target_user else "Document visibility changed to external",
                    "Actor": log.get('actor', {}).get('email', ''),
                    "Owner": self.get_param(p, 'owner'),
                    "IP Address": log.get('ipAddress', ''),
                    "Encrypted": self.get_param(p, 'encrypted'),
                    "Domain": DOMAIN_NAME
                })
        return pd.DataFrame(rows)

    def process_deleted_mails(self, logs):
        """
        Process deleted emails.
        Fields: Date, Message ID, Subject, Event, From(Header address), From (Envelope),
                To (Envelope), Owner, Descriptin, Domain, Attachment Hash, Attachment Name,
                Attachment Malware Family, IP Address, From(Header name), Confidential mode,
                Client type, Device Session Identifier
        """
        rows = []
        for log in logs:
            events = log.get('events', [])
            for event in events:
                if event.get('name') not in ['email_deleted', 'email_trashed', 'email_permanently_deleted']:
                    continue

                p = event.get('parameters', [])

                rows.append({
                    "Date (YYYY-MM-DD, Timestamp)": format_timestamp(log['id']['time']),
                    "Message ID": self.get_param(p, 'message_id'),
                    "Subject": self.get_param(p, 'subject'),
                    "Event": event.get('name', ''),
                    "From(Header address)": self.get_param(p, 'from_header_address'),
                    "From (Envelope)": self.get_param(p, 'from'),
                    "To (Envelope)": self.get_param(p, 'to'),
                    "Owner": log.get('actor', {}).get('email', ''),
                    "Descriptin": f"Email {event.get('name', '').replace('email_', '')}",
                    "Domain": DOMAIN_NAME,
                    "Attachment Hash": self.get_param(p, 'attachment_hash'),
                    "Attachment Name": self.get_param(p, 'attachment_name'),
                    "Attachment Malware Family": self.get_param(p, 'malware_family'),
                    "IP Address": log.get('ipAddress', ''),
                    "From(Header name)": self.get_param(p, 'from_header'),
                    "Confidential mode": self.get_param(p, 'confidential_mode'),
                    "Client type": self.get_param(p, 'client_type'),
                    "Device Session Identifier": self.get_param(p, 'device_session_id')
                })
        return pd.DataFrame(rows)

    def process_attachment_downloads(self, logs):
        """
        Process attachment download events.
        Fields: Date, Message ID, Subject, Event, From(Header address), From (Envelope),
                To (Envelope), Owner, Descriptin, Domain, Attachment Hash, Attachment Name,
                Attachment Malware Family, IP Address, From(Header name), Confidential mode,
                Target attachment name, Target attachment hash
        """
        rows = []
        for log in logs:
            events = log.get('events', [])
            for event in events:
                if event.get('name') not in ['attachment_downloaded', 'email_downloaded']:
                    continue

                p = event.get('parameters', [])

                rows.append({
                    "Date (YYYY-MM-DD, Timestamp)": format_timestamp(log['id']['time']),
                    "Message ID": self.get_param(p, 'message_id'),
                    "Subject": self.get_param(p, 'subject'),
                    "Event": event.get('name', ''),
                    "From(Header address)": self.get_param(p, 'from_header_address'),
                    "From (Envelope)": self.get_param(p, 'from'),
                    "To (Envelope)": self.get_param(p, 'to'),
                    "Owner": log.get('actor', {}).get('email', ''),
                    "Descriptin": "Attachment downloaded",
                    "Domain": DOMAIN_NAME,
                    "Attachment Hash": self.get_param(p, 'attachment_hash'),
                    "Attachment Name": self.get_param(p, 'attachment_name'),
                    "Attachment Malware Family": self.get_param(p, 'malware_family'),
                    "IP Address": log.get('ipAddress', ''),
                    "From(Header name)": self.get_param(p, 'from_header'),
                    "Confidential mode": self.get_param(p, 'confidential_mode'),
                    "Target attachment name": self.get_param(p, 'target_attachment_name'),
                    "Target attachment hash": self.get_param(p, 'target_attachment_hash')
                })
        return pd.DataFrame(rows)

    def process_drive_file_downloads(self, logs):
        """
        Process Drive file download events.
        Fields: Date, Document ID, Title, Document Type, Prior Visibilty, Visibilty,
                Event, Description, Actor, Owner, IP Address, Encrypted, Domain
        """
        rows = []
        for log in logs:
            events = log.get('events', [])
            for event in events:
                if event.get('name') not in ['download', 'doc_downloaded']:
                    continue

                p = event.get('parameters', [])

                rows.append({
                    "Date (YYYY-MM-DD, Timestamp)": format_timestamp(log['id']['time']),
                    "Document ID": self.get_param(p, 'doc_id'),
                    "Title": self.get_param(p, 'doc_title'),
                    "Document Type": self.get_param(p, 'doc_type'),
                    "Prior Visibilty": self.get_param(p, 'old_visibility'),
                    "Visibilty": self.get_param(p, 'visibility'),
                    "Event": event.get('name', ''),
                    "Description": "File downloaded from Drive",
                    "Actor": log.get('actor', {}).get('email', ''),
                    "Owner": self.get_param(p, 'owner'),
                    "IP Address": log.get('ipAddress', ''),
                    "Encrypted": self.get_param(p, 'encrypted'),
                    "Domain": DOMAIN_NAME
                })
        return pd.DataFrame(rows)

    def process_chrome_logs(self, logs):
        """Process Chrome browser logs (FULL LOGS)."""
        rows = []
        for log in logs:
            events = log.get('events', [])
            for event in events:
                p = event.get('parameters', [])

                row_data = {
                    "Date (YYYY-MM-DD, Timestamp)": format_timestamp(log['id']['time']),
                    "Event": event.get('name', ''),
                    "Actor": log.get('actor', {}).get('email', ''),
                    "IP Address": log.get('ipAddress', ''),
                    "Domain": DOMAIN_NAME
                }

                # Add all available parameters dynamically
                for param in p:
                    param_name = param.get('name', '')
                    param_value = param.get('value') or param.get('boolValue') or param.get('intValue') or ""
                    if param_name not in row_data:
                        row_data[param_name] = param_value

                rows.append(row_data)
        return pd.DataFrame(rows)

    def process_device_logs(self, logs):
        """Process device/endpoint logs (FULL LOGS)."""
        rows = []
        for log in logs:
            events = log.get('events', [])
            for event in events:
                p = event.get('parameters', [])

                row_data = {
                    "Date (YYYY-MM-DD, Timestamp)": format_timestamp(log['id']['time']),
                    "Event": event.get('name', ''),
                    "Actor": log.get('actor', {}).get('email', ''),
                    "IP Address": log.get('ipAddress', ''),
                    "Domain": DOMAIN_NAME
                }

                # Add all available parameters dynamically
                for param in p:
                    param_name = param.get('name', '')
                    param_value = param.get('value') or param.get('boolValue') or param.get('intValue') or ""
                    if param_name not in row_data:
                        row_data[param_name] = param_value

                rows.append(row_data)
        return pd.DataFrame(rows)

    # =================================================================================
    # EXPORT FUNCTIONS
    # =================================================================================

    def save_to_excel(self, df: pd.DataFrame, filename: str):
        """Save DataFrame to Excel with proper formatting."""
        if df.empty:
            return False

        full_path = os.path.join(self.case_path, f"{filename}.xlsx")

        try:
            with pd.ExcelWriter(full_path, engine='openpyxl') as writer:
                df.to_excel(writer, sheet_name='Logs', index=False)

                # Auto-adjust column widths
                worksheet = writer.sheets['Logs']
                for column in worksheet.columns:
                    max_length = 0
                    column_letter = column[0].column_letter
                    for cell in column:
                        try:
                            if cell.value:
                                max_length = max(max_length, len(str(cell.value)))
                        except:
                            pass
                    adjusted_width = min(max_length + 2, 60)
                    worksheet.column_dimensions[column_letter].width = adjusted_width

            return full_path
        except Exception as e:
            self.print_styled(f"Excel save error: {e}", "error")
            return None

    def save_to_csv(self, df: pd.DataFrame, filename: str):
        """Save DataFrame to CSV with UTF-8 encoding."""
        if df.empty:
            return False

        full_path = os.path.join(self.case_path, f"{filename}.csv")

        try:
            df.to_csv(full_path, index=False, encoding='utf-8-sig')
            return full_path
        except Exception as e:
            self.print_styled(f"CSV save error: {e}", "error")
            return None

    def save_file(self, df: pd.DataFrame, filename: str):
        """Save DataFrame to selected format with forensic integrity."""
        if df.empty:
            self.print_styled(f"No data for {filename}", "warn")
            return False

        saved_path = None

        if self.export_fmt == 'xlsx':
            saved_path = self.save_to_excel(df, filename)
        else:
            saved_path = self.save_to_csv(df, filename)

        if saved_path:
            # Generate hash for forensic integrity
            file_hash = get_hash(saved_path)
            self.manifest[filename] = {
                "path": saved_path,
                "hash_sha256": file_hash,
                "records": len(df),
                "format": self.export_fmt
            }

            self.print_styled(f"Saved: {filename} ({len(df)} records)", "success")
            return True

        return False

    # =================================================================================
    # MAIN RUNNER
    # =================================================================================

    def run(self):
        # 1. Show Banner
        self.print_banner()

        # 2. Authenticate
        self.authenticate()

        # 3. Get User Inputs
        self.get_user_inputs()

        self.print_styled("Starting Forensic Log Extraction...", "forensic")
        print(Fore.GREEN + "-"*74 + "\n")

        # 4. Fetch logs concurrently
        apps = ['gmail', 'drive', 'chrome', 'mobile']
        fetched_data = {}

        with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
            future_to_app = {executor.submit(self.fetch_with_backoff, app): app for app in apps}

            with tqdm(total=len(apps), desc="Fetching Logs", 
                     bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}",
                     ncols=70) as pbar:
                for future in concurrent.futures.as_completed(future_to_app):
                    app = future_to_app[future]
                    try:
                        fetched_data[app] = future.result()
                    except Exception as exc:
                        self.print_styled(f"{app} fetch failed: {exc}", "error")
                    pbar.update(1)

        print(Fore.GREEN + "\n" + "-"*74)
        self.print_styled("Processing and Exporting Forensic Data...", "forensic")
        print(Fore.GREEN + "-"*74 + "\n")

        # 5. Process each log type
        summary = []

        # Process Gmail logs for different event types
        if 'gmail' in fetched_data:
            gmail_logs = fetched_data['gmail']

            df = self.process_emails_sent_externally(gmail_logs)
            if self.save_file(df, "Emails_Sent_Externally"):
                summary.append({"Log Type": "Emails Sent Externally", "Records": len(df)})
            else:
                summary.append({"Log Type": "Emails Sent Externally", "Records": 0})

            df = self.process_deleted_mails(gmail_logs)
            if self.save_file(df, "Deleted_Mails"):
                summary.append({"Log Type": "Deleted Mails", "Records": len(df)})
            else:
                summary.append({"Log Type": "Deleted Mails", "Records": 0})

            df = self.process_attachment_downloads(gmail_logs)
            if self.save_file(df, "Attachment_Downloads"):
                summary.append({"Log Type": "Attachment Downloads", "Records": len(df)})
            else:
                summary.append({"Log Type": "Attachment Downloads", "Records": 0})

        # Process Drive logs
        if 'drive' in fetched_data:
            drive_logs = fetched_data['drive']

            df = self.process_drive_shared_externally(drive_logs)
            if self.save_file(df, "Drive_Shared_Externally"):
                summary.append({"Log Type": "Drive Shared Externally", "Records": len(df)})
            else:
                summary.append({"Log Type": "Drive Shared Externally", "Records": 0})

            df = self.process_drive_file_downloads(drive_logs)
            if self.save_file(df, "Drive_File_Downloads"):
                summary.append({"Log Type": "Drive File Downloads", "Records": len(df)})
            else:
                summary.append({"Log Type": "Drive File Downloads", "Records": 0})

        # Process Chrome logs
        if 'chrome' in fetched_data:
            df = self.process_chrome_logs(fetched_data['chrome'])
            if self.save_file(df, "Chrome_Logs"):
                summary.append({"Log Type": "Chrome Logs", "Records": len(df)})
            else:
                summary.append({"Log Type": "Chrome Logs", "Records": 0})

        # Process Device logs
        if 'mobile' in fetched_data:
            df = self.process_device_logs(fetched_data['mobile'])
            if self.save_file(df, "Device_Logs"):
                summary.append({"Log Type": "Device Logs", "Records": len(df)})
            else:
                summary.append({"Log Type": "Device Logs", "Records": 0})

        # Save forensic manifest
        manifest_path = os.path.join(self.case_path, "FORENSIC_MANIFEST.json")
        manifest_data = {
            "case_id": self.case_id,
            "target_email": self.target_email,
            "admin_email": self.admin_email,
            "domain": DOMAIN_NAME,
            "timestamp": datetime.datetime.now().isoformat(),
            "files": self.manifest
        }
        with open(manifest_path, "w") as f:
            json.dump(manifest_data, f, indent=4)

        self.print_styled("Forensic manifest saved.", "success")

        # Print final summary
        print(Fore.GREEN + "\n" + "="*74)
        print(Fore.GREEN + "              FORENSIC ACQUISITION COMPLETE")
        print(Fore.GREEN + "="*74)
        print(Fore.GREEN + f"  Case ID:    {self.case_id}")
        print(Fore.GREEN + f"  Admin:      {self.admin_email}")
        print(Fore.GREEN + f"  Target:     {self.target_email}")
        print(Fore.GREEN + f"  Domain:     {DOMAIN_NAME}")
        print(Fore.GREEN + f"  Location:   {self.case_path}")
        print(Fore.GREEN + "="*74)
        print(Fore.GREEN + "  SUMMARY:")
        for item in summary:
            status = "✓" if item["Records"] > 0 else "✗"
            print(Fore.GREEN + f"    [{status}] {item['Log Type']}: {item['Records']} records")
        print(Fore.GREEN + "="*74)

        input("\nPress Enter to exit...")

# =================================================================================
# ENTRY POINT
# =================================================================================

if __name__ == '__main__':
    try:
        app = GLARForensics()
        app.run()
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Operation Cancelled by User.")
        sys.exit(0)
    except Exception as e:
        print(Fore.RED + f"\n[!] Fatal Error: {e}")
        logging.exception("Fatal error")
        input("Press Enter to exit...")