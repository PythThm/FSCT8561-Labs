import socketio

sio = socketio.Client()


@sio.event
def connect():
    print("Connected to server")

    # Send a message to the server
    sio.emit("message", "Hello from the client!")


@sio.event
def disconnect():
    print("Disconnected from server")


@sio.event
def message(data):
    print("Server says:", data)


sio.connect("http://localhost:5000")
sio.wait()
