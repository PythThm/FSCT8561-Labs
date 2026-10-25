"""
What is logged: time, remote address, username, event name, outcome.
What is NEVER logged: passwords, one-time codes, TOTP secrets, message text.
Cmon its the stuff I have from the doc 
"""

import os
import re
import threading
from datetime import datetime

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "security_events.log")

_lock = threading.Lock()


def _clean_username(value):
    """
    Assume all users are untrusted, prvent crafted injection for fake logs (why bother?)
    """
    if not value:
        return "-"
    return re.sub(r"[^A-Za-z0-9_.\-]", "?", str(value))[:32]


def format_addr(addr):
    try:
        return f"{addr[0]}:{addr[1]}"
    except (TypeError, IndexError):
        return "-"


def log_event(event, addr=None, username=None, outcome="-"):
    """Append one line to the log. Only fixed event names and outcomes are passed in."""
    line = " | ".join([
        datetime.now().isoformat(timespec="seconds"),
        format_addr(addr),
        _clean_username(username),
        event,
        outcome,
    ])
    try:
        with _lock:
            with open(LOG_FILE, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
    except OSError:
        # Logging must never crash the server; the console still shows the event.
        pass
    print("[LOG]", line)