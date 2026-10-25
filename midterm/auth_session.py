import datetime
import hashlib
import hmac
import json
import os
import re
import threading
import time

import pyotp

from security_log import log_event

USERS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.json")

PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 16

MAX_CONNECTION_FAILURES = 3   # failures on one connection before it is closed
MAX_USER_FAILURES = 5         # failures per username inside the window ...
USER_FAILURE_WINDOW = 300     # ... of this many seconds trigger a lockout
LOCKOUT_SECONDS = 60

OTP_PATTERN = re.compile(r"[0-9]{6}")

# Session states
CONNECTED = "CONNECTED"
PASSWORD_VERIFIED = "PASSWORD_VERIFIED"
AUTHENTICATED = "AUTHENTICATED"

# Used when the username does not exist, so an unknown user costs the same time
# as a real one and response timing does not reveal which usernames are valid.
_DUMMY_SALT = os.urandom(SALT_BYTES)


def hash_password(password, salt, iterations=PBKDF2_ITERATIONS):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)


def new_user_record(password):
    """Build the stored record for a new user (used by setup_users.py)."""
    salt = os.urandom(SALT_BYTES)
    return {
        "salt": salt.hex(),
        "iterations": PBKDF2_ITERATIONS,
        "hash": hash_password(password, salt).hex(),
        "totp_secret": pyotp.random_base32(),
    }


class UserStore:
    """Read-only view of users.json, loaded once at startup (not part of the source code)."""

    def __init__(self, path=USERS_FILE):
        with open(path, encoding="utf-8") as handle:
            self._users = json.load(handle)["users"]

    def get(self, username):
        return self._users.get(username)


class AttemptTracker:
    """
    Counts failures per username and applies a temporary lockout.
    Names are tracked whether or not the account exists, so a lockout message
    cannot be used to discover valid usernames. Counters live in memory only
    (a known residual risk, see T6).
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._failures = {}
        self._locked_until = {}

    def is_locked(self, username):
        with self._lock:
            return time.time() < self._locked_until.get(username, 0)

    def record_failure(self, username):
        now = time.time()
        with self._lock:
            recent = [t for t in self._failures.get(username, []) if now - t < USER_FAILURE_WINDOW]
            recent.append(now)
            if len(recent) >= MAX_USER_FAILURES:
                self._locked_until[username] = now + LOCKOUT_SECONDS
                recent = []
            self._failures[username] = recent

    def record_success(self, username):
        with self._lock:
            self._failures.pop(username, None)


class OtpReplayGuard:
    """Remembers the last accepted TOTP time-step per user so a code works only once."""

    def __init__(self):
        self._lock = threading.Lock()
        self._last_step = {}

    def accept(self, username, step):
        with self._lock:
            if step <= self._last_step.get(username, -1):
                return False
            self._last_step[username] = step
            return True


def _check_totp(secret, code):
    """
    Return the matching TOTP time-step, or None.
    Equivalent to pyotp's verify(code, valid_window=1) (current step +/- 1 for
    clock drift) but it also tells us WHICH step matched, which the replay guard needs.
    """
    totp = pyotp.TOTP(secret)
    current = totp.timecode(datetime.datetime.now())
    matched = None
    for step in (current - 1, current, current + 1):
        # compare_digest is constant-time; every step is checked, no early exit.
        if hmac.compare_digest(totp.generate_otp(step), code):
            matched = step
    return matched


class Session:
    """State for ONE client connection. Destroyed when the connection closes."""

    def __init__(self, store, tracker, replay_guard, addr):
        self.store = store
        self.tracker = tracker
        self.replay_guard = replay_guard
        self.addr = addr
        self.state = CONNECTED
        self.username = None
        self.failures = 0

    def is_authenticated(self):
        return self.state == AUTHENTICATED

    def _fail(self, event, username, reset_to_connected):
        """Common failure path. Returns (reply, close_connection)."""
        self.tracker.record_failure(username)
        self.failures += 1
        if reset_to_connected:
            # A failed AUTH must not leave an earlier password success usable.
            self.state = CONNECTED
            self.username = None
        log_event(event, self.addr, username, "FAILURE")
        if self.failures >= MAX_CONNECTION_FAILURES:
            log_event("TOO_MANY_FAILURES", self.addr, username, "CONNECTION_CLOSED")
            return "ACCESS_DENIED", True
        return "ACCESS_DENIED", False

    def handle_auth(self, username, password):
        """Step 1: password. Returns (reply, close_connection)."""
        if self.tracker.is_locked(username):
            log_event("LOGIN_LOCKED", self.addr, username, "REFUSED")
            return "ERROR|LOCKED|Too many failures, try again later", False

        record = self.store.get(username)
        if record is not None:
            salt = bytes.fromhex(record["salt"])
            iterations = record["iterations"]
            stored_hash = bytes.fromhex(record["hash"])
        else:
            salt, iterations, stored_hash = _DUMMY_SALT, PBKDF2_ITERATIONS, b""

        candidate = hash_password(password, salt, iterations)
        # compare_digest avoids leaking how many leading bytes matched.
        password_ok = record is not None and hmac.compare_digest(candidate, stored_hash)

        if not password_ok:
            return self._fail("LOGIN_FAILED", username, reset_to_connected=True)

        self.state = PASSWORD_VERIFIED
        self.username = username
        log_event("PASSWORD_OK", self.addr, username, "OTP_REQUIRED")
        return "OTP_REQUIRED", False

    def handle_otp(self, code):
        """Step 2: TOTP code. Only reached from PASSWORD_VERIFIED. Returns (reply, close)."""
        record = self.store.get(self.username)
        step = _check_totp(record["totp_secret"], code)

        if step is None:
            return self._fail("OTP_FAILED", self.username, reset_to_connected=False)

        if not self.replay_guard.accept(self.username, step):
            # Right code, but it was already used: treat as a failure (replay).
            return self._fail("OTP_REPLAY_REJECTED", self.username, reset_to_connected=False)

        self.state = AUTHENTICATED
        self.tracker.record_success(self.username)
        log_event("LOGIN_SUCCESS", self.addr, self.username, "AUTHENTICATED")
        return "ACCESS_GRANTED", False