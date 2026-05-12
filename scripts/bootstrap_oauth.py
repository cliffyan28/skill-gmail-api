#!/usr/bin/env python3
"""
One-time OAuth bootstrap script — RUN THIS ON YOUR LOCAL MAC, NOT ON SERVER.

This script opens a browser for Google OAuth consent and obtains a refresh_token.
Copy the output GMAIL_REFRESH_TOKEN to your server's environment.

Usage:
    python3 bootstrap_oauth.py

Scopes requested (only these 3):
    - https://www.googleapis.com/auth/gmail.readonly
    - https://www.googleapis.com/auth/gmail.compose
    - https://www.googleapis.com/auth/gmail.send

No other scopes. No gmail.modify, no gmail.settings.basic.
"""

import json
import os
import sys

# Only these 3 scopes — matching what the server-side auth.py uses
SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.compose",
    "https://www.googleapis.com/auth/gmail.send",
]

CREDS_FILE = "credentials.json"


def main():
    from google_auth_oauthlib.flow import InstalledAppFlow

    # Check credentials file exists
    if not os.path.exists(CREDS_FILE):
        print(f"ERROR: {CREDS_FILE} not found.")
        print("")
        print("To set up OAuth credentials:")
        print("  1. Go to https://console.cloud.google.com/apis/credentials")
        print("  2. Create an OAuth 2.0 Client ID (Desktop app type)")
        print(f"  3. Download the JSON and save as '{CREDS_FILE}' in this folder")
        print("  4. Run this script again")
        sys.exit(1)

    print("=" * 60)
    print("Gmail OAuth Bootstrap")
    print("=" * 60)
    print("")
    print("Requesting ONLY these 3 scopes:")
    for s in SCOPES:
        print(f"  - {s}")
    print("")
    print("A browser will open for Google sign-in and consent.")
    print("After consent, your refresh_token will be printed below.")
    print("")
    print("DO NOT share this token — it gives full Gmail access.")
    print("=" * 60)
    print("")

    flow = InstalledAppFlow.from_client_secrets_file(CREDS_FILE, SCOPES)
    creds = flow.run_local_server(port=0)

    print("✅ OAuth successful!")
    print("")
    print("Your refresh_token is:")
    print("-" * 40)
    print(creds.refresh_token)
    print("-" * 40)
    print("")
    print("Add this to your server's environment as:")
    print(f"  export GMAIL_REFRESH_TOKEN='{creds.refresh_token}'")
    print("")
    print("Also set GMAIL_CLIENT_ID and GMAIL_CLIENT_SECRET from the same")
    print("credentials.json file (or from Google Cloud Console).")


if __name__ == "__main__":
    main()