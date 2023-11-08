# Building a secure reddit / discussion forum (but with a focus on security)

import asyncio
import logging
from enum import Enum

import websockets
from cryptography.fernet import Fernet
from Message import Message, MessageType, decode_json, encode_json

logging.basicConfig(
    format="%(message)s",
    level=logging.INFO,
)

# Replace these keys with securely generated keys
SECRET_KEY = b"UoJQgRHVAZas_m2TtDJYOIpYf6lbqB6VtCL4BD1_dU0="
cipher_suite = Fernet(SECRET_KEY)

# State to be kept track of by the server

# active connections
connections = set()

# Map a username to a public key
users = dict()

# Map thread id to state associated with each thread
threads = dict()


async def message_handler(websocket, path):
    async for message_str in websocket:
        try:
            message: Message = decode_json(message_str)
        except:
            print("Failed to parse message")

        logging.debug(f"Received message: {message}")

        if message.message_type == "REGISTER":
            username = message.data["username"]
            public_key = message.data["public_key"]
            users[username] = public_key
            message.data["sender"] = username
            message.data["status"] = "Registered successfully"
            await websocket.send(encode_json(message))
            print(f"Registered {username}")
        elif message.message_type == "CREATE_THREAD":
            thread_id = message.data["thread_id"]
            sender_username = message.data["sender"]
            if thread_id in threads:
                message.status = "Thread already exists"
            else:
                threads[thread_id] = {
                    "messages": [],
                    "users": set(),
                    "creator": sender_username,
                }
                threads[thread_id]["users"].add(sender_username)
                message.status = "Thread created successfully"
            message.sender = sender_username
            await websocket.send(encode_json(message))
            print(f"Created thread {thread_id}")
        elif message.message_type == MessageType.JOIN_THREAD:
            thread_id = message.data["thread_id"]
            sender_username = message.data["sender"]
            if thread_id not in threads:
                message.status = "Thread does not exist"
            else:
                threads[thread_id]["users"].add(sender_username)
                message.status = "Joined thread successfully"
            message.sender = sender_username
            await websocket.send(encode_json(message))
            print(f"User {sender_username} joined thread {thread_id}")
        elif message.message_type == MessageType.LEAVE_THREAD:
            thread_id = message.data["thread_id"]
            sender_username = message.data["sender"]
            if thread_id not in threads:
                message.status = "Thread does not exist"
            else:
                threads[thread_id]["users"].remove(sender_username)
                message.status = "Left thread successfully"
            message.sender = sender_username
            await websocket.send(encode_json(message))
            print(f"User {sender_username} left thread {thread_id}")
        elif message.message_type == MessageType.SEND_MESSAGE:
            thread_id = message.data["thread_id"]
            sender_username = message.data["sender"]
            if thread_id not in threads:
                message.status = "Thread does not exist"
            else:
                threads[thread_id]["messages"].append(message.data["message"])
                message.status = "Message sent successfully"
            message.sender = sender_username
            await websocket.send(encode_json(message))
            print(f"User {sender_username} sent message to thread {thread_id}")
        elif message.message_type == MessageType.GET_MESSAGES:
            thread_id = message.data["thread_id"]
            sender_username = message.data["sender"]
            if thread_id not in threads:
                message.status = "Thread does not exist"
            else:
                message.data["messages"] = threads[thread_id]["messages"]
                message.status = "Messages retrieved successfully"
            message.sender = sender_username
            await websocket.send(encode_json(message))
            print(f"User {sender_username} retrieved messages from thread {thread_id}")
        elif message.message_type == MessageType.GET_THREADS:
            sender_username = message.data["sender"]
            message.data["threads"] = list(threads.keys())
            message.status = "Threads retrieved successfully"
            message.sender = sender_username
            await websocket.send(encode_json(message))
            print(f"User {sender_username} retrieved threads")
        else:
            print("Received invalid message")

        # log state
        logging.info(f"Users: {users}")
        logging.info(f"Threads: {threads}")
        logging.info(f"Connections: {connections}")


start_server = websockets.serve(message_handler, "localhost", 8765)

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
