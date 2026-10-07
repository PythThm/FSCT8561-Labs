import socket

from getpass import getpass

# Globla vars
HOST = "127.0.0.1"
PORT = 12345

# Connect to auth server
client_socket = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

client_socket.connect((HOST, PORT))
print("Connected to Auth server")

try:
    authenticated = False

    # Prompt for user login
    while not authenticated:
        username = input("Username: ")
        password = getpass("Password: ")
        print("Username:", username)
        print("Password was collected without echoing it.")

        # Auth request
        auth_message = "AUTH|" + username + "|" + password
        client_socket.send(
            auth_message.encode()
        )

        # Server respond
        response = client_socket.recv(1024).decode()
        print("Server: ", response)

        # OTP request
        if response == "OTP_REQUIRED":
            otp = input("Enter OTP: ")
            otp_message = "OTP|" + otp
            client_socket.send(
                otp_message.encode()
            )

            response = client_socket.recv(1024).decode()
            print("Server:", response)

            if response == "ACCESS_GRANTED":
                authenticated = True
                print("Authentication successful")
                print("You can now send message to server")
            else:
                print("Auth failed")
                print("Please try again.\n")

        elif response == "ACCESS_DENIED":
            print("Authentication failed.")
            print("Please try again.\n")
        else:
            print("Authentication failed.")
            print("Please try again.\n")

    # Message loop
    while authenticated:
        message = input(
            "Enter message or type EXIT to leave: "
        )

        # EXITING
        if message.upper() == "EXIT":
            client_socket.send(
                "EXIT|".encode()
            )
            response = client_socket.recv(1024)
            print(
                "Server:",
                response.decode()
            )
            authenticated = False
        else:
            protocol_message = "MSG|" + message
            client_socket.send(
                protocol_message.encode()
            )
            response = client_socket.recv(1024)
            print(
                "Server:",
                response.decode()
            )
finally:
    client_socket.close()
    print("Connection closed.")
