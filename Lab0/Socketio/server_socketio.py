import socketio
from aiohttp import web

# Create the Socket.IO server
sio = socketio.AsyncServer(
    async_mode="aiohttp",
    cors_allowed_origins="*"
)

# App start
app = web.Application()
sio.attach(app)

# Send message to client when connected
@sio.event
async def connect(sid, environ):
    print(f"Client connected: {sid}")
    await sio.emit("message", "Welcome!", to=sid)

# Logs when client disconnects 
@sio.event
async def disconnect(sid):
    print(f"Client disconnected: {sid}")

# Handles message from client
@sio.event
async def message(sid, data):
    print(f"Received from {sid}: {data}")

    # Send a response back to that client
    await sio.emit(
        "message",
        f"Server received: {data}",
        to=sid
    )


if __name__ == "__main__":
    web.run_app(app, host="0.0.0.0", port=5000)
