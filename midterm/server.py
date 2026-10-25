import re
import socket
import threading

from auth_session import (AUTHENTICATED, CONNECTED, PASSWORD_VERIFIED, AttemptTracker,
                          OtpReplayGuard, Session, UserStore)
from pcap_analyzer import PcapUnavailable, analyze_pcap
from protocol import (MAX_FRAME, MAX_REQUEST, SERVER_HOST, SERVER_PORT, ConnectionClosed,
                      IdleTimeout, ProtocolError, recv_frame, send_frame)
from security_log import log_event

MAX_CLIENTS = 1               # simultaneous connections (limits memory and threads)
IDLE_TIMEOUT = 120            # seconds of silence before a client is dropped
FRAME_TIMEOUT = 10            # seconds allowed to finish a frame once it has started
MAX_PROTOCOL_ERRORS = 5       # consecutive bad requests before the connection is closed

USERNAME_PATTERN = re.compile(r"[A-Za-z0-9_.\-]+")
OTP_PATTERN = re.compile(r"[0-9]{6}")
MAX_USERNAME = 32
MAX_PASSWORD = 128
MAX_MESSAGE = 200

COMMANDS = {"AUTH", "OTP", "PCAP", "MSG", "EXIT"}

# Default-deny table: which commands each state may use (matches the state table in A.4).
ALLOWED = {
    CONNECTED: {"AUTH", "EXIT"},
    PASSWORD_VERIFIED: {"OTP", "AUTH", "EXIT"},
    AUTHENTICATED: {"PCAP", "MSG", "EXIT"},
}
PROTECTED = {"PCAP", "MSG"}


def error(code, text):
    """Fixed, short error replies: no stack traces, paths, or echoed user input."""
    return f"ERROR|{code}|{text}"


def process_request(session, text):
    """
    Handle one decoded request.
    Returns (reply, close_connection, is_protocol_error).
    """
    command = text.split("|", 1)[0]

    # 1. Exact match against the allowlist.
    if command not in COMMANDS:
        log_event("UNKNOWN_COMMAND", session.addr, session.username, "REJECTED")
        return error("UNKNOWN_COMMAND", "Unknown command"), False, True

    # 2. Authorization gate, checked BEFORE any field is parsed or any handler runs.
    if command not in ALLOWED[session.state]:
        log_event("UNAUTHORIZED_COMMAND", session.addr, session.username, f"{command}_IN_{session.state}")
        if command in PROTECTED:
            return error("AUTH_REQUIRED", "Authentication required"), False, True
        if command == "OTP":
            return "ACCESS_DENIED", False, True   # OTP before a successful AUTH
        return error("AUTH_REQUIRED", "Command not allowed in this state"), False, True

    # 3. Handlers (each validates its own fields).
    if command == "EXIT":
        if text not in ("EXIT", "EXIT|"):
            return error("FORMAT", "Invalid request"), False, True
        log_event("LOGOUT", session.addr, session.username, "OK")
        return "OK|Goodbye", True, False

    if command == "AUTH":
        # Split into at most 3 parts so a password containing "|" stays intact.
        parts = text.split("|", 2)
        if len(parts) != 3:
            return error("FORMAT", "Invalid request"), False, True
        username, password = parts[1], parts[2]
        if len(username) > MAX_USERNAME or len(password) > MAX_PASSWORD:
            return error("TOO_LONG", "Field too long"), False, True
        if not USERNAME_PATTERN.fullmatch(username) or password == "":
            return error("FORMAT", "Invalid request"), False, True
        reply, close = session.handle_auth(username, password)
        return reply, close, False

    if command == "OTP":
        parts = text.split("|", 1)
        if len(parts) != 2 or not OTP_PATTERN.fullmatch(parts[1]):
            return error("FORMAT", "Invalid request"), False, True
        reply, close = session.handle_otp(parts[1])
        return reply, close, False

    if command == "PCAP":
        if text != "PCAP":
            return error("FORMAT", "Invalid request"), False, True
        log_event("PCAP_REQUEST", session.addr, session.username, "STARTED")
        try:
            report = analyze_pcap()
        except PcapUnavailable as problem:
            # Details go to the server console only; the client gets a fixed message.
            print("[PCAP]", problem)
            log_event("PCAP_FAILED", session.addr, session.username, "UNAVAILABLE")
            return error("PCAP_UNAVAILABLE", "Capture could not be analyzed"), False, False
        reply = "OK|" + report
        if len(reply.encode("utf-8")) > MAX_FRAME:
            reply = reply.encode("utf-8")[: MAX_FRAME - 80].decode("utf-8", "ignore") + "\n[output truncated]"
        log_event("PCAP_REQUEST", session.addr, session.username, "COMPLETED")
        return reply, False, False

    if command == "MSG":
        parts = text.split("|", 1)
        if len(parts) != 2 or parts[1] == "":
            return error("FORMAT", "Invalid request"), False, True
        if len(parts[1]) > MAX_MESSAGE:
            return error("TOO_LONG", "Message too long"), False, True
        # Only the length is logged, never the message text.
        log_event("MSG_RECEIVED", session.addr, session.username, f"LEN_{len(parts[1])}")
        return f"OK|Message received from {session.username}", False, False

    # Unreachable (command is always in COMMANDS), kept so nothing falls through silently.
    return error("SERVER", "Internal error"), True, False


def handle_client(conn, addr, store, tracker, replay_guard, slots):
    """One thread per connection. Everything here is isolated from other clients."""
    session = Session(store, tracker, replay_guard, addr)
    protocol_errors = 0
    log_event("CONNECT", addr, None, "ACCEPTED")
    try:
        while True:
            try:
                payload = recv_frame(conn, IDLE_TIMEOUT, FRAME_TIMEOUT, max_size=MAX_REQUEST)
            except IdleTimeout:
                log_event("IDLE_TIMEOUT", addr, session.username, "CLOSED")
                break
            except ConnectionClosed:
                log_event("CLIENT_DISCONNECTED", addr, session.username, "CLOSED")
                break
            except ProtocolError as problem:
                # We cannot find the next frame boundary, so the connection is closed.
                log_event(problem.event, addr, session.username, "CLOSED")
                break

            try:
                text = payload.decode("utf-8")
            except UnicodeDecodeError:
                reply, close, is_error = error("FORMAT", "Invalid request"), False, True
            else:
                reply, close, is_error = process_request(session, text)

            protocol_errors = protocol_errors + 1 if is_error else 0
            if protocol_errors >= MAX_PROTOCOL_ERRORS:
                log_event("TOO_MANY_ERRORS", addr, session.username, "CLOSED")
                send_frame(conn, error("FORMAT", "Too many invalid requests"))
                break

            send_frame(conn, reply)
            if close:
                break

    except (ConnectionResetError, BrokenPipeError):
        log_event("CLIENT_DISCONNECTED", addr, session.username, "RESET")
    except Exception as problem:
        # Any unexpected bug: log only the exception type, tell the client nothing useful.
        log_event("SERVER_ERROR", addr, session.username, type(problem).__name__)
        try:
            send_frame(conn, error("SERVER", "Internal error"))
        except OSError:
            pass
    finally:
        conn.close()
        slots.release()
        log_event("DISCONNECT", addr, session.username, "SESSION_DESTROYED")


def main():
    try:
        store = UserStore()
    except (OSError, ValueError, KeyError):
        # Without a user store nobody could log in, so refuse to start.
        print("Error: users.json is missing or unreadable. Run setup_users.py first.")
        return

    tracker = AttemptTracker()
    replay_guard = OtpReplayGuard()
    slots = threading.BoundedSemaphore(MAX_CLIENTS)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Bind to localhost ONLY: the service is not reachable from other machines.
    listener.bind((SERVER_HOST, SERVER_PORT))
    listener.listen(5)
    print(f"Operation Sentinel server listening on {SERVER_HOST}:{SERVER_PORT} (Ctrl+C to stop)")

    try:
        while True:
            conn, addr = listener.accept()
            if not slots.acquire(blocking=False):
                log_event("CONNECT", addr, None, "REFUSED_SERVER_FULL")
                conn.close()
                continue
            threading.Thread(
                target=handle_client,
                args=(conn, addr, store, tracker, replay_guard, slots),
                daemon=True,
            ).start()
    except KeyboardInterrupt:
        print("\nServer stopping.")
    finally:
        listener.close()


if __name__ == "__main__":
    main()