# Building a secure reddit / discussion forum (but with a focus on security)

import asyncio
import websockets
from cryptography.fernet import Fernet
import json
from enum import Enum

# Replace these keys with securely generated keys
SECRET_KEY = b"UoJQgRHVAZas_m2TtDJYOIpYf6lbqB6VtCL4BD1_dU0="
cipher_suite = Fernet(SECRET_KEY)


class MessageType(Enum):
    REGISTER = "REGISTER"
    CREATE_THREAD = "CREATE_THREAD"
    JOIN_THREAD = "JOIN_THREAD"
    LEAVE_THREAD = "LEAVE_THREAD"
    SEND_MESSAGE = "SEND_MESSAGE"
    GET_MESSAGES = "GET_MESSAGES"
    GET_THREADS = "GET_THREADS"


class Message:
    def __init__(self, message_type, data):
        self.message_type = message_type
        self.data = data
        self.sender = None

    def __str__(self):
        return f"Message(message_type={self.message_type}, data={self.data})"

    def __repr__(self):
        return str(self)

    def to_json(self):
        return {
            "message_type": self.message_type,
            "data": self.data,
        }

    @classmethod
    def from_json(cls, json):
        return cls(json["message_type"], json["data"])


def encode_json(message: Message) -> str:
    return json.dumps(message.to_json())


def decode_json(json_string: str) -> Message:
    return Message.from_json(json.loads(json_string))


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

            if message.message_type == MessageType.REGISTER:
                username = message.data["username"]
                public_key = message.data["public_key"]
                users[username] = public_key
                message.sender = username
                message.status = "Registered successfully"
                await websocket.send(encode_json(message))
                print(f"Registered {username}")
            elif message.message_type == MessageType.CREATE_THREAD:
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
        except:
            print("Received invalid message")
            continue

        # decrypted_message = cipher_suite.decrypt(message_str.encode()).decode()
        # print(f"Received encrypted message: {message_str}")
        # print(f"Decrypted message: {decrypted_message}")

        # # Echo back the decrypted message
        # encrypted_message = cipher_suite.encrypt(decrypted_message.encode()).decode()
        # await websocket.send(encrypted_message)


start_server = websockets.serve(message_handler, "localhost", 8765)

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
