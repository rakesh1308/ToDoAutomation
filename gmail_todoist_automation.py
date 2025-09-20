# file: app.py
import os, re, time, json, base64, pickle, sys, traceback
from typing import Dict, Any, Optional

# --- 3rd-party deps ---
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from todoist_api_python.api import TodoistAPI

# OpenAI: works with legacy SDK (openai.ChatCompletion) or new SDK (client.chat.completions)
# If you use "openai>=1.0", switch to the new style below.
try:
    import openai
    OPENAI_NEW_SDK = False
except Exception:
    from openai import OpenAI
    OPENAI_NEW_SDK = True

# --------------------------- Config ---------------------------
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

# Required:
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
TODOIST_API_TOKEN = os.environ.get("TODOIST_API_TOKEN", "")
GMAIL_LABEL = os.environ.get("GMAIL_LABEL", "")  # e.g., "FromAutomation" or "INBOX/SubLabel"

# OAuth client as ENV (recommended for Railway):
# Put the **exact** JSON you download from GCP (OAuth 2.0 Client ID -> Desktop App) into this var,
# base64-encoded to avoid quoting issues. Example: base64(credentials.json) -> GOOGLE_OAUTH_CLIENT_JSON_B64
GOOGLE_OAUTH_CLIENT_JSON_B64 = os.environ.get("GOOGLE_OAUTH_CLIENT_JSON_B64", "")

# Optional: use a file path fallback if you really want a file (less reliable on PaaS)
CREDENTIALS_JSON_PATH = os.environ.get("CREDENTIALS_JSON_PATH", "credentials.json")

# Where to persist Google token (Railway filesystem is ephemeral unless you attach a Volume)
TOKEN_PATH = os.environ.get("TOKEN_PATH", "token.json")

# Polling interval seconds
POLL_SECONDS = int(os.environ.get("POLL_SECONDS", "60"))

# Local vs headless auth:
RUN_MODE = os.environ.get("RUN_MODE", "headless")  # "local" -> launches browser, "headless" -> paste code into console

# ------------------------ Helpers ----------------------------

def _fail(msg: str):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.stderr.flush()
    sys.stdout.flush()
    time.sleep(0.5)
    sys.exit(1)

def _parse_oauth_client_from_env_or_file() -> Dict[str, Any]:
    """
    Prefer GOOGLE_OAUTH_CLIENT_JSON_B64; fall back to reading CREDENTIALS_JSON_PATH.
    Performs robust checks so HTML/PDF/ZIP can't sneak in.
    """
    if GOOGLE_OAUTH_CLIENT_JSON_B64:
        try:
            raw = base64.b64decode(GOOGLE_OAUTH_CLIENT_JSON_B64)
        except Exception as e:
            raise RuntimeError(f"GOOGLE_OAUTH_CLIENT_JSON_B64 is not valid base64: {e}")
    else:
        # Fallback to file (not recommended on Railway)
        if not os.path.exists(CREDENTIALS_JSON_PATH):
            raise RuntimeError(
                "No GOOGLE_OAUTH_CLIENT_JSON_B64 and credentials file not found at "
                f"{CREDENTIALS_JSON_PATH}."
            )
        with open(CREDENTIALS_JSON_PATH, "rb") as f:
            raw = f.read()

    # Quick wrong-file checks
    prefix = raw[:20].lower()
    if raw.startswith(b"%PDF"):
        raise RuntimeError("OAuth JSON appears to be a PDF. Download the actual JSON from GCP.")
    if raw.startswith(b"PK"):
        raise RuntimeError("OAuth JSON looks like a ZIP. Unzip and use the JSON inside.")
    if prefix.startswith(b"<!doctype html") or prefix.startswith(b"<html"):
        raise RuntimeError("OAuth JSON is actually an HTML page. Download the raw JSON file.")

    # Decode tolerant of BOM/UTF-16
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        try:
            text = raw.decode("utf-16")
        except UnicodeDecodeError:
            raise RuntimeError("OAuth JSON is not valid UTF-8/UTF-16 text.")

    try:
        data = json.loads(text)
    except Exception as e:
        raise RuntimeError(f"OAuth JSON cannot be parsed: {e}")

    # Expect keys like "installed" for Desktop client
    if not any(k in data for k in ("installed", "web")):
        # Some downloads wrap it differently, but Desktop apps should have "installed"
        # If your JSON is nested, allow that here:
        raise RuntimeError("OAuth JSON missing 'installed' or 'web' section. Ensure it's a Desktop app client.")

    return data

def _google_auth() -> Any:
    """
    Returns a Gmail API service client, storing token to TOKEN_PATH.
    Headless-safe by default (prints URL, expects code in console).
    """
    creds = None
    if os.path.exists(TOKEN_PATH):
        try:
            with open(TOKEN_PATH, "rb") as f:
                creds = pickle.load(f)
        except Exception:
            # Corrupt token; ignore so we can recreate
            creds = None

    if not creds or not getattr(creds, "valid", False):
        if creds and getattr(creds, "expired", False) and getattr(creds, "refresh_token", None):
            creds.refresh(Request())
        else:
            client_config = _parse_oauth_client_from_env_or_file()
            flow = InstalledAppFlow.from_client_config(client_config, SCOPES)
            if RUN_MODE.lower() == "local":
                # Opens a browser; good for laptop
                creds = flow.run_local_server(port=0)
            else:
                # Headless: prints a URL + asks for code in the logs/console
                print("Headless OAuth: open the URL below, authorize, then paste the code here:")
                creds = flow.run_console()

        with open(TOKEN_PATH, "wb") as f:
            pickle.dump(creds, f)

    service = build("gmail", "v1", credentials=creds)
    return service

def _init_todoist() -> TodoistAPI:
    if not TODOIST_API_TOKEN:
        _fail("TODOIST_API_TOKEN is not set.")
    return TodoistAPI(TODOIST_API_TOKEN)

def _init_openai():
    if not OPENAI_API_KEY:
        _fail("OPENAI_API_KEY is not set.")
    if OPENAI_NEW_SDK:
        client = OpenAI(api_key=OPENAI_API_KEY)
        return client
    else:
        openai.api_key = OPENAI_API_KEY
        return None

def _gmail_list_label_unread(service, label_name: str) -> list:
    q = f'label:"{label_name}" is:unread'
    res = service.users().messages().list(userId="me", q=q).execute()
    return res.get("messages", [])

def _gmail_get(service, msg_id: str) -> Dict[str, Any]:
    return service.users().messages().get(userId="me", id=msg_id, format="full").execute()

def _gmail_mark_read(service, msg_id: str):
    service.users().messages().modify(
        userId="me", id=msg_id, body={"removeLabelIds": ["UNREAD"]}
    ).execute()

def _extract_plain_body(payload: Dict[str, Any]) -> str:
    """
    Best-effort plain text extraction; falls back to stripping HTML if needed.
    """
    import base64 as b64
    from html import unescape

    def decode_part(_part):
        data = _part.get("body", {}).get("data", "")
        if not data:
            return ""
        try:
            return b64.urlsafe_b64decode(data.encode("utf-8")).decode("utf-8", errors="replace")
        except Exception:
            return ""

    # multipart
    if "parts" in payload:
        # Prefer text/plain
        for p in payload["parts"]:
            if p.get("mimeType") == "text/plain":
                return decode_part(p)
        # Fallback to first part’s text content (strip HTML)
        for p in payload["parts"]:
            text = decode_part(p)
            if text:
                # quick de-HTML
                return unescape(re.sub(r"<[^>]+>", " ", text))
    # single part
    if payload.get("mimeType") == "text/plain":
        return decode_part(payload)
    if payload.get("mimeType", "").startswith("text/"):
        text = decode_part(payload)
        return unescape(re.sub(r"<[^>]+>", " ", text))
    return ""

def _headers_lookup(headers: list, name: str, default: str = "") -> str:
    return next((h["value"] for h in headers if h.get("name", "").lower() == name.lower()), default)

def _ai_summarize_to_task(openai_client, email: Dict[str, str]) -> Dict[str, Optional[str]]:
    """
    Calls GPT to structure: TITLE, DESCRIPTION, PRIORITY, DUE_DATE
    """
    system = "You turn emails into concise, well-structured Todoist tasks."
    user = f"""From: {email['from']}
Subject: {email['subject']}

Body:
{email['body']}

Format exactly:
TITLE: <short task title>
DESCRIPTION: <detailed task description>
PRIORITY: <High|Medium|Low>
DUE_DATE: <natural-language due date if present, else None>"""

    if OPENAI_NEW_SDK:
        resp = openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role":"system","content":system},{"role":"user","content":user}],
            temperature=0.2,
            max_tokens=300,
        )
        content = resp.choices[0].message.content
    else:
        resp = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role":"system","content":system},{"role":"user","content":user}],
            temperature=0.2,
            max_tokens=300,
        )
        content = resp.choices[0].message.content

    # Parse
    title = re.search(r"^TITLE:\s*(.*)$", content, re.MULTILINE)
    desc = re.search(r"^DESCRIPTION:\s*([\s\S]*?)^\s*PRIORITY:", content, re.MULTILINE)
    prio = re.search(r"^PRIORITY:\s*(High|Medium|Low)", content, re.IGNORECASE | re.MULTILINE)
    due  = re.search(r"^DUE_DATE:\s*(.*)$", content, re.MULTILINE)

    return {
        "title": (title.group(1).strip() if title else "Untitled Task"),
        "description": (desc.group(1).strip() if desc else content.strip()),
        "priority": (prio.group(1).capitalize() if prio else "Medium"),
        "due_date": (d.strip() if (due and (d := due.group(1)) and d.strip().lower() != "none") else None),
    }

def _todoist_priority_num(p: str) -> int:
    return {"High": 4, "Medium": 2, "Low": 1}.get(p, 2)

def _process_one_message(service, todoist_api, openai_client, message_id: str):
    m = _gmail_get(service, message_id)
    payload = m.get("payload", {})
    headers = payload.get("headers", [])
    subject = _headers_lookup(headers, "Subject", "No Subject")
    sender = _headers_lookup(headers, "From", "Unknown")

    body = _extract_plain_body(payload)
    if not body.strip():
        print(f"[skip] Empty body: {subject}")
        _gmail_mark_read(service, message_id)
        return

    email_obj = {"from": sender, "subject": subject, "body": body}
    task = _ai_summarize_to_task(openai_client, email_obj)

    full_description = (
        f"{task['description']}\n\n"
        f"--- Email Context ---\nFrom: {sender}\nSubject: {subject}"
    )
    todoist_api.add_task(
        content=task["title"],
        description=full_description[:9000],  # safety
        priority=_todoist_priority_num(task["priority"]),
        due_string=task["due_date"],
        labels=["FromEmail"]
    )
    print(f"[ok] Created task: {task['title']}")
    _gmail_mark_read(service, message_id)

def main_loop():
    if not GMAIL_LABEL:
        _fail("GMAIL_LABEL is not set.")
    if not TODOIST_API_TOKEN:
        _fail("TODOIST_API_TOKEN is not set.")
    if not OPENAI_API_KEY:
        _fail("OPENAI_API_KEY is not set.")

    gmail = _google_auth()
    todoist_api = _init_todoist()
    openai_client = _init_openai()

    print(f"Worker started. Polling label: {GMAIL_LABEL} every {POLL_SECONDS}s")
    while True:
        try:
            msgs = _gmail_list_label_unread(gmail, GMAIL_LABEL)
            if not msgs:
                print("[idle] No new emails")
            else:
                for msg in msgs:
                    try:
                        _process_one_message(gmail, todoist_api, openai_client, msg["id"])
                        time.sleep(1)  # mild throttle
                    except Exception as e:
                        print(f"[err] Failed message {msg.get('id')}: {e}")
                        traceback.print_exc()
            sys.stdout.flush()
        except Exception as e:
            print(f"[loop err] {e}")
            traceback.print_exc()
        time.sleep(POLL_SECONDS)

if __name__ == "__main__":
    main_loop()
