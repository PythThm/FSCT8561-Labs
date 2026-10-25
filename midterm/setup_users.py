"""
setup_users.py - one-time creation of users.json (run before starting the server).

The lab hard-coded the user "alice" and her password in the source code and made
a new random TOTP secret on every start. Here the credentials live in a separate
file (salted hash + a fixed TOTP secret), so an authenticator app can be enrolled
once and keep working.

The TOTP secret is shown ONCE on screen so it can be entered in an authenticator
app (Google Authenticator, Authy, ...). Nothing else prints or logs it.

From my current lab, I am currently hard coding the user and password in source code
and 
"""

import json
import os
import re
import sys
from getpass import getpass

import pyotp

from auth_session import USERS_FILE, new_user_record

USERNAME_PATTERN = re.compile(r"[A-Za-z0-9_.\-]{1,32}")


def main():
    if os.path.exists(USERS_FILE):
        answer = input(f"{os.path.basename(USERS_FILE)} already exists. Overwrite? (y/N): ").strip().lower()
        if answer != "y":
            print("Nothing changed.")
            return

    username = input("Username (letters, digits, _ . -, max 32): ").strip()
    if not USERNAME_PATTERN.fullmatch(username):
        print("Error: invalid username.")
        sys.exit(1)

    password = getpass("Password (8-128 characters): ")
    if getpass("Repeat password: ") != password:
        print("Error: passwords do not match.")
        sys.exit(1)
    if not 8 <= len(password) <= 128:
        print("Error: password must be 8-128 characters.")
        sys.exit(1)

    record = new_user_record(password)
    with open(USERS_FILE, "w", encoding="utf-8") as handle:
        json.dump({"users": {username: record}}, handle, indent=2)
    try:
        os.chmod(USERS_FILE, 0o600)  # owner read/write only (no effect on Windows)
    except OSError:
        pass

    uri = pyotp.TOTP(record["totp_secret"]).provisioning_uri(name=username, issuer_name="Operation Sentinel")
    print("\nUser created. Enroll an authenticator app NOW (this is shown only once):")
    print("  Secret key :", record["totp_secret"])
    print("  Setup URI  :", uri)


if __name__ == "__main__":
    main()