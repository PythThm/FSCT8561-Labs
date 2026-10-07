import socket
import hashlib
import pyotp
import time

# Globla vars
HOST = "127.0.0.1"
PORT = 12345

# Password functions
def hash_password(password):
    return hashlib.sha256(
        password.encode()
    ).hexdigest()

def verify_password(password, stored_hash):
    entered_hash = hash_password(password)
    return entered_hash == stored_hash

# OTP function
def verify_otp(secret, otp):
    totp = pyotp.TOTP(secret)
    return totp.verify(otp)

# User database
stored_hash = hash_password("Cyber123!")
secret = pyotp.random_base32()
user = {
    "alice": {
        "password_hash": stored_hash,
        "totp_secret": secret
    }
}

# Server setup
server_socket = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

# Fix for OSError 98
server_socket.setsockopt(
    socket.SOL_SOCKET,
    socket.SO_REUSEADDR, 1
)

server_socket.bind((HOST, PORT))
server_socket.listen(1)

print("Server is waiting for a connection...")

client_socket, client_address = server_socket.accept()

print("Connected by:", client_address)

# Connection state
username = None
authenticated = False
password_verified = False
connected = True

# Main server loop
while connected:
    try:
        data = client_socket.recv(1024)

        if not data:
            print("Client disconnected unexpectedly")
            break

        message = data.decode().strip()

        print("Received:", message)

        # AUTH command
        # Expected:
        # AUTH|username|password
        if message.startswith("AUTH"):

            parts = message.split("|")

            # Validate structure before using fields
            if len(parts) != 3 or parts[0] != "AUTH":
                client_socket.send(
                    "ERROR|Invalid AUTH format".encode()
                )
                continue

            username = parts[1]
            password = parts[2]

            # Check for empty username/password
            if username == "" or password == "":
                client_socket.send(
                    "ERROR|Username and password required".encode()
                )
                password_verified = False
                authenticated = False
                continue

            # Check whether username exists
            if username not in user:
                client_socket.send(
                    "ERROR|Invalid username or password".encode()
                )
                password_verified = False
                authenticated = False
                continue

            # Get stored password hash
            stored_hash = user[username]["password_hash"]

            # Hash submitted password and compare
            if verify_password(password, stored_hash):
                password_verified = True
                authenticated = False # Password done, not OTP

                user_secret = user[username]["totp_secret"] # Get aice's secret

                # Create otp, print in server terminal
                totp = pyotp.TOTP(user_secret)
                current_otp = totp.now()
                print("Current OTP:", current_otp)

                # Ask for OTP
                client_socket.send(
                    "OTP_REQUIRED".encode()
                )
                print(
                    "Password verified for:", username
                )
            else:
                password_verified = False
                authenticated = False
                client_socket.send(
                    "ACCESS_DENIED".encode()
                )
                print(
                    "Password verificatioqn failed for: ", username
                )

        # OTP command
        # Expected:
        # OTP|123456
        elif message.startswith("OTP"):
            parts = message.split("|")

            # Validate OTP structure
            if len(parts) != 2 or parts[0] != "OTP":
                client_socket.send(
                    "ERROR|Invalid OTP format".encode()
                )
                continue

            otp = parts[1].strip()

            # Checking for password stage is completed
            if not password_verified:
                client_socket.send(
                    "ACCESS_DENIED".encode()
                )
                print(
                    "Password Stage not complete, OTP aborted"
                )
                continue

            # Validate OTP is six digits
            if len(otp) != 6 or not otp.isdigit():
                client_socket.send(
                    "ERROR|OTP must be six digits".encode()
                )
                print("OTP must be exactly 6 digits")
                continue

            # Get user's TOTP secret
            user_secret = user[username]["totp_secret"]

            print("OTP received from client:", otp)


            # Verify OTP
            if verify_otp(user_secret, otp):
                authenticated = True
                password_verified = True

                client_socket.send(
                    "ACCESS_GRANTED".encode()
                )

                print(
                    username,
                    "successfully authenticated"
                )

            else:
                authenticated = False
                client_socket.send(
                    "ERROR ACCESS DENIED".encode()
                )
                print(
                    "Invalid or expired OTP for: ", username
                )

        # MSG command
        elif message.startswith("MSG"):

            parts = message.split("|", 1)

            if len(parts) != 2:
                client_socket.send(
                    "ERROR|Invalid command format".encode()
                )
                continue

            content = parts[1]

            # User must complete authentication first
            if not authenticated:
                client_socket.send(
                    "ERROR|Authentication required".encode()
                )
                continue

            if content == "":
                client_socket.send(
                    "ERROR|Message cannot be empty".encode()
                )

            elif len(content) > 200:
                client_socket.send(
                    "ERROR|Message too long".encode()
                )

            else:
                print(username + " says:", content)

                client_socket.send(
                    (
                        "OK|Message received from "
                        + username
                    ).encode()
                )

        # EXIT command
        elif message.startswith("EXIT"):
            client_socket.send(
                "OK|Goodbye".encode()
            )
            connected = False

        # Unknown command
        else:
            client_socket.send(
                "ERROR|Unknown command".encode()
            )

    except ConnectionResetError:
        print("Connection reset by client")
        break


# Close connection
client_socket.close()
server_socket.close()

print("Server closed")