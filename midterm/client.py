import re
import socket
from getpass import getpass
from http_checker import run_http_checks
from protocol import (MAX_FRAME, SERVER_HOST, SERVER_PORT, ConnectionClosed, IdleTimeout, ProtocolError, recv_frame, send_frame)
from scanner import run_port_scan

CONNECT_TIMEOUT = 5
RESPONSE_TIMEOUT = 60       # PCAP analysis can take a while

USERNAME_PATTERN = re.compile(r"[A-Za-z0-9_.\-]{1,32}")
OTP_PATTERN = re.compile(r"[0-9]{6}")
MAX_PASSWORD = 128
MAX_MESSAGE = 200


def request(sock, text):
    """Send one command and return the server's reply as text."""
    send_frame(sock, text)
    payload = recv_frame(sock, RESPONSE_TIMEOUT, max_size=MAX_FRAME)
    return payload.decode("utf-8", errors="replace")


def reply_kind(reply):
    return reply.split("|", 1)[0]


def show_error(reply):
    """Print the text part of an ERROR|CODE|text reply."""
    parts = reply.split("|", 2)
    print("Server:", parts[2] if len(parts) == 3 else reply)


def login(sock):
    """Password then OTP. Returns True when the server grants access."""
    while True:
        username = input("Username: ").strip()
        if not USERNAME_PATTERN.fullmatch(username):
            print("Username must be 1-32 letters, digits, '_', '.' or '-'.")
            continue
        password = getpass("Password: ")        # not echoed, never printed
        if not 1 <= len(password) <= MAX_PASSWORD:
            print(f"Password must be 1-{MAX_PASSWORD} characters.")
            continue

        reply = request(sock, f"AUTH|{username}|{password}")
        del password

        if reply == "OTP_REQUIRED":
            code = input("Enter the 6-digit code from your authenticator app: ").strip()
            if not OTP_PATTERN.fullmatch(code):
                print("The code must be exactly six digits.")
                continue
            reply = request(sock, f"OTP|{code}")
            if reply == "ACCESS_GRANTED":
                print("Authentication successful.")
                return True
            print("Authentication failed. Please try again.\n")
        elif reply == "ACCESS_DENIED":
            print("Authentication failed. Please try again.\n")
        elif reply_kind(reply) == "ERROR":
            show_error(reply)
            if "LOCKED" in reply:
                return False
        else:
            print("Unexpected reply from server.")
            return False


def ask_port(label):
    return input(f"{label} port: ").strip()


def menu(sock):
    while True:
        print("\n=== Operation Sentinel ===")
        print("1. Scan local TCP ports (client-side)")
        print("2. Check the local test website (client-side)")
        print("3. Analyze the PCAP on the server")
        print("4. Send a diagnostic message to the server")
        print("5. Exit")
        choice = input("Choose: ").strip()

        if choice == "1":
            run_port_scan(ask_port("Start"), ask_port("End"))
        elif choice == "2":
            run_http_checks()
        elif choice == "3":
            reply = request(sock, "PCAP")
            if reply_kind(reply) == "OK":
                print(reply.split("|", 1)[1])
            else:
                show_error(reply)
        elif choice == "4":
            text = input("Message (1-200 characters): ")
            if not 1 <= len(text) <= MAX_MESSAGE:
                print(f"Message must be 1-{MAX_MESSAGE} characters.")
                continue
            reply = request(sock, f"MSG|{text}")
            print("Server:", reply.split("|", 1)[1] if reply_kind(reply) == "OK" else reply)
        elif choice == "5":
            print("Server:", request(sock, "EXIT|").split("|", 1)[-1])
            return
        else:
            print("Please choose 1-5.")


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(CONNECT_TIMEOUT)
    try:
        sock.connect((SERVER_HOST, SERVER_PORT))
    except (ConnectionRefusedError, socket.timeout):
        print(f"Cannot reach the server at {SERVER_HOST}:{SERVER_PORT}. Is server.py running?")
        sock.close()
        return
    print("Connected to the Operation Sentinel server.")

    try:
        if login(sock):
            menu(sock)
    except (ConnectionClosed, ConnectionError, IdleTimeout, ProtocolError):
        # Server stopped, closed the connection (for example after too many failures), or timed out.
        print("\nServer disconnected. Please restart the client.")
    except (KeyboardInterrupt, EOFError):
        print("\nExiting.")
        try:
            request(sock, "EXIT|")
        except Exception:
            pass
    finally:
        sock.close()
        print("Connection closed.")


if __name__ == "__main__":
    main()