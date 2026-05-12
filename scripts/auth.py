"""OAuth 2.0 authentication for Gmail API via env vars."""

import os
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

# Strictly only these 3 scopes — no gmail.modify, no gmail.settings.basic
SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.compose",
    "https://www.googleapis.com/auth/gmail.send",
]

# Env vars — must be set before use
REFRESH_TOKEN = os.environ.get("GMAIL_REFRESH_TOKEN")
CLIENT_ID = os.environ.get("GMAIL_CLIENT_ID")
CLIENT_SECRET = os.environ.get("GMAIL_CLIENT_SECRET")


def require_env(name: str) -> str:
    """Get env var or raise clear error."""
    val = os.environ.get(name)
    if not val:
        raise RuntimeError(f"Missing required env var: {name}")
    return val


def build_credentials():
    """Build Credentials from env vars (no file-based OAuth)."""
    refresh_token = require_env("GMAIL_REFRESH_TOKEN")
    client_id = require_env("GMAIL_CLIENT_ID")
    client_secret = require_env("GMAIL_CLIENT_SECRET")

    creds = Credentials(
        token=None,
        refresh_token=refresh_token,
        client_id=client_id,
        client_secret=client_secret,
        token_uri="https://oauth2.googleapis.com/token",
        scopes=SCOPES,
    )
    return creds


def get_credentials() -> Credentials:
    """Get valid credentials, refreshing as needed."""
    creds = build_credentials()

    if not creds.valid:
        creds.refresh(Request())

    return creds


def get_gmail_service():
    """Get authenticated Gmail API service."""
    creds = get_credentials()
    return build("gmail", "v1", credentials=creds)