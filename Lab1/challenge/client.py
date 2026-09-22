import socket
import threading

HOST = "127.0.0.1"
PORT = 12345

client_socket = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

client_socket.connect((HOST, PORT))

username = input("Enter your username: ")

client_socket.send(
    ("HELLO|" + username).encode()
)

response = client_socket.recv(1024)
print("Server:", response.decode())


def receive_messages():
    while True:
        try:
            data = client_socket.recv(1024)

            if not data:
                print("Disconnected from server")
                break

            print("\nServer:", data.decode())

        except ConnectionResetError:
            print("Connection closed")
            break


# Start receiving thread
receive_thread = threading.Thread(
    target=receive_messages,
    daemon=True
)

receive_thread.start()


while True:

    message = input("> ")

    if message.upper() == "EXIT":

        client_socket.send(
            "EXIT|".encode()
        )

        response = client_socket.recv(1024)

        print("Server:", response.decode())

        break

    client_socket.send(
        ("MSG|" + message).encode()
    )


client_socket.close()
print("Disconnected")