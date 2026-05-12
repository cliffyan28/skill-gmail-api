---
name: skill-gmail-api
description: |
  Gmail API skill for reading, drafting, and sending emails via CLI.
  Supports reading, drafting, sending, archiving, labeling, and batch operations.
  ⚠️ SHADOW_MODE=true by default — all sends become drafts unless disabled.
  4 safety guards: shadow mode, whitelist, circuit breaker, daily quota.
allowed-tools:
  - Execute
---

# Gmail API Skill (OpenClaw Fork)

Modified from tmustier/skill-gmail-api — adapted for server-side headless use with 4 safety guards.

## Safety Guards (all ON by default)

| Guard | Default | Env Var | Description |
|-------|---------|---------|-------------|
| Shadow Mode | ON | `SHADOW_MODE=true/false` | All sends → drafts instead |
| Whitelist | OFF | `config/whitelist.yaml` | Block non-listed recipients |
| Circuit Breaker | ON | (always on) | Keywords → force draft |
| Daily Quota | 20/day | `DAILY_SEND_QUOTA=N` | Max sends per day |

## Environment Variables (required)

```bash
GMAIL_REFRESH_TOKEN=   # From bootstrap_oauth.py
GMAIL_CLIENT_ID=      # From Google Cloud Console
GMAIL_CLIENT_SECRET=  # From Google Cloud Console
SHADOW_MODE=true      # default: ON (recommended)
DAILY_SEND_QUOTA=20   # max sends per day
```

## Commands

```bash
# Read
scripts/gmail.py read --limit 10
scripts/gmail.py read --query "is:unread" --full
scripts/gmail.py get --id MSG_ID

# Draft
scripts/gmail.py draft --to "x@y.com" --subject "Hi" --body "Hello"
scripts/gmail.py draft --reply-to MSG_ID --body "Thanks!"

# Send (always goes through safety guards)
scripts/gmail.py send --draft-id DRAFT_ID
scripts/gmail.py send --to "x@y.com" --subject "Hi" --body "Hello"

# Status
scripts/gmail.py status   # Show guard status + quota remaining

# Manage
scripts/gmail.py archive --id MSG_ID
scripts/gmail.py trash --id MSG_ID
scripts/gmail.py list_labels

# Batch
scripts/gmail.py batch-archive --query "from:newsletters@"
scripts/gmail.py batch-mark-read --query "is:unread from:notifications@"
```

## Setup

1. **One-time OAuth (run on your Mac, not server):**
   ```bash
   python3 scripts/bootstrap_oauth.py
   ```
   This opens browser for Google OAuth consent. Copy the `GMAIL_REFRESH_TOKEN` output.

2. **Set env vars on server:**
   ```bash
   export GMAIL_REFRESH_TOKEN='...'
   export GMAIL_CLIENT_ID='...'
   export GMAIL_CLIENT_SECRET='...'
   export SHADOW_MODE=true
   export DAILY_SEND_QUOTA=20
   ```

3. **Optional: Configure whitelist**
   ```bash
   cp config/whitelist.yaml.example config/whitelist.yaml
   # Edit whitelist.yaml and add approved email addresses
   ```

## Safety Guard Details

### Shadow Mode (`SHADOW_MODE=true`)
When ON, any `send` command creates a draft instead of sending.  
When OFF, sends go through whitelist check first.

### Whitelist (`config/whitelist.yaml`)
List approved recipient emails. Non-listed recipients are blocked (shadowed to draft) when `SHADOW_MODE=false`.

### Circuit Breaker (always ON)
Triggered by keywords: 签约/合同/转账/汇款/付款/[¥$€£]\d+  
Forces draft + alert regardless of other settings.

### Daily Quota (`DAILY_SEND_QUOTA`)
Max sends per day. Exceeding forces all sends to draft.

## OAuth Scopes (exactly 3)

Only these 3 scopes are requested — no more, no less:
- `gmail.readonly` — read emails
- `gmail.compose` — create drafts
- `gmail.send` — send emails

## Audit Log

All send/draft operations are logged to:
```
logs/gmail-audit-YYYY-MM-DD.jsonl
```

Format per line:
```json
{"timestamp": "...", "action": "send", "to": "...", "subject": "...", "shadow_mode": true, "blocked_by": null}
```

Logs retained for 90 days (configure log rotation externally).