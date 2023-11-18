import asyncio
import json
import logging

import eventlet
import socketio

sio = socketio.Server(cors_allowed_origins="*")
app = socketio.WSGIApp(sio)
logging.basicConfig(level=logging.INFO)


class ChatServer:
    def __init__(self):
        self.user_public_key = dict()
        self.user_socket = dict()
        self.thread_id_to_users = dict()
        self.thread_id_to_messages = dict()
        self.thread_id_to_creator = dict()

    @sio.event
    async def handle_key_upload(self, sid, message):
        try:
            username = message["username"]
            public_key = message["public_key"]
        except:
            logging.error(f"Invalid key_upload message: {message}")

        self.user_public_key[username] = public_key
        self.user_socket[username] = sid

        message["action"] = "key_upload_response"
        message["status"] = "Registered successfully"
        sio.emit("message", json.dumps(message), room=sid)
        logging.info(f"User registered: {username}")

    @sio.event
    async def handle_thread_create(self, sid, message):
        try:
            thread_id = message["thread_id"]
            username = message["username"]
        except:
            logging.error(f"Invalid create_thread: {message}")

        if thread_id in self.thread_id_to_users:
            message["status"] = "Thread already exists"
        else:
            self.thread_id_to_users[thread_id] = set()
            self.thread_id_to_messages[thread_id] = []
            self.thread_id_to_users[thread_id].add(username)
            self.thread_id_to_creator[thread_id] = username
            message["status"] = "Thread created successfully"

        message["action"] = "thread_create_response"
        sio.emit("message", json.dumps(message), room=sid)
        logging.info(f"Created thread {thread_id}")

    # Similar modifications for other message handling functions...

    async def message_handler(self, sid, message):
        try:
            message = json.loads(message)
        except:
            logging.error("Failed to parse message from client:  {message}")

        if message["action"] == "key_upload":
            await self.handle_key_upload(sid, message)
        elif message["action"] == "create_thread":
            await self.handle_thread_create(sid, message)
        # Add handling for other message types...


def main():
    server = ChatServer()
    eventlet.wsgi.server(eventlet.listen(("localhost", 8765)), app)


if __name__ == "__main__":
    eventlet.monkey_patch()
    main()
