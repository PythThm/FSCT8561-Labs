import socket
import threading

HOST = "127.0.0.1"
PORT = 12345

server_socket = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

server_socket.bind((HOST, PORT))
server_socket.listen()

print("Server is waiting for connections...")

# Store connected clients:
# {client_socket: username}
clients = {}


def broadcast(message, sender_socket):
    """Send a message to every client except the sender."""

    for client_socket in list(clients):
        if client_socket != sender_socket:
            try:
                client_socket.send(message.encode())
            except:
                # Remove clients that can no longer be reached
                clients.pop(client_socket, None)


def handle_client(client_socket, client_address):
    """Handle communication with one client."""

    username = None
    connected = True

    print("Connected by:", client_address)

    while connected:
        try:
            data = client_socket.recv(1024)

            if not data:
                print("Client disconnected unexpectedly")
                break

            message = data.decode()

            print("Received:", message)

            # Check command format
            if "|" not in message:
                client_socket.send(
                    "ERROR|Invalid command format".encode()
                )
                continue

            command, content = message.split("|", 1)

            # HELLO command
            if command == "HELLO":

                if content == "":
                    client_socket.send(
                        "ERROR|Username required".encode()
                    )

                else:
                    username = content
                    clients[client_socket] = username

                    print("Username:", username)

                    client_socket.send(
                        ("OK|Hello " + username).encode()
                    )

            # MSG command
            elif command == "MSG":

                if username is None:
                    client_socket.send(
                        "ERROR|HELLO required first".encode()
                    )

                elif content == "":
                    client_socket.send(
                        "ERROR|Message cannot be empty".encode()
                    )

                elif len(content) > 200:
                    client_socket.send(
                        "ERROR|Message too long".encode()
                    )

                else:
                    chat_message = (
                        username + ": " + content
                    )

                    print(chat_message)

                    # Send message to other clients
                    broadcast(
                        chat_message,
                        client_socket
                    )

                    # Optional confirmation to sender
                    client_socket.send(
                        "OK|Message sent".encode()
                    )

            # EXIT command
            elif command == "EXIT":

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
            print(
                "Connection reset by:",
                client_address
            )
            break

        except Exception as e:
            print("Error:", e)
            break

    # Remove client from server state
    clients.pop(client_socket, None)

    client_socket.close()

    print("Connection closed:", client_address)


# Main server loop
while True:

    client_socket, client_address = server_socket.accept()

    # Create a thread for this client
    client_thread = threading.Thread(
        target=handle_client,
        args=(client_socket, client_address)
    )

    client_thread.start()

    print(
        "Active threads:",
        threading.active_count() - 1
    )