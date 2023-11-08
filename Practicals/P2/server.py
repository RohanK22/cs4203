import asyncio
import json
import logging

import websockets


class ChatServer:
    def __init__(self):
        self.groups = dict()

        self.user_public_key = dict()
        self.user_socket = dict()

        self.thread_id_to_users = dict()
        self.thread_id_to_messages = dict()
        self.thread_id_to_creator = dict()

    # Save public key for user
    async def handle_key_upload(self, sender_websocket, message):
        try:
            username = message["username"]
            public_key = message["public_key"]
        except:
            logging.error("Invalid key_upload message: {message}")

        self.user_public_key[username] = public_key
        self.user_socket[username] = sender_websocket

        message["action"] = "key_upload_response"
        message["status"] = "Registered successfully"
        await sender_websocket.send(json.dumps(message))
        logging.info("User registered: {username}")

    # Create a thread
    async def handle_thread_create(self, sender_websocket, message):
        # TODO: Check if user exists / registered

        try:
            thread_id = message["thread_id"]
            username = message["username"]
        except:
            logging.error("Invalid create_thread: {message}")
        if thread_id in self.thread_id_to_users:
            message["status"] = "Thread already exists"
        else:
            self.thread_id_to_users[thread_id] = set()
            self.thread_id_to_messages[thread_id] = []
            self.thread_id_to_users[thread_id].add(username)
            self.thread_id_to_creator[thread_id] = username
            message["status"] = "Thread created successfully"

        message["action"] = "thread_create_response"
        await sender_websocket.send(json.dumps(message))
        logging.info(f"Created thread {thread_id}")

    # Join a thread
    async def handle_thread_join(self, sender_websocket, message):
        # TODO: Do ECDH to get shared key from group creator
        try:
            thread_id = message["thread_id"]
            username = message["username"]
        except:
            logging.error("Invalid join_thread: {message}")

        if thread_id not in self.thread_id_to_users:
            message["status"] = "Thread does not exist"
        else:
            self.thread_id_to_users[thread_id].add(username)
            message["status"] = "Joined thread successfully"

        message["action"] = "thread_join_response"
        await sender_websocket.send(json.dumps(message))
        logging.info(f"User {username} joined thread {thread_id}")

    # Leave a thread
    async def handle_thread_leave(self, sender_websocket, message):
        # TODO: Might have to reset shared key
        try:
            thread_id = message["thread_id"]
            username = message["username"]
        except:
            logging.error("Invalid leave_thread: {message}")

        if thread_id not in self.thread_id_to_users:
            message["status"] = "Thread does not exist"
        else:
            self.thread_id_to_users[thread_id].remove(username)
            message["status"] = "Left thread successfully"

        message["action"] = "thread_leave_resonse"
        await sender_websocket.send(json.dumps(message))
        logging.info(f"User {username} left thread {thread_id}")

    # Send a message to a thread
    async def handle_thread_send_message(self, sender_websocket, message):
        try:
            thread_id = message["thread_id"]
            username = message["username"]
            message_content = message["message"]
        except:
            logging.error("Invalid thread_send_message: {message}")

        if thread_id not in self.thread_id_to_users:
            message["status"] = "Thread does not exist"
        else:
            self.thread_id_to_messages[thread_id].append((username, message["message"]))

            # for user in self.thread_id_to_users[thread_id]:
            #     if user != username:
            #         message["action"] = "incoming_message"
            #         self.user_socket[user].send(json.dumps(message))
            message["status"] = "Message sent successfully"

        message["action"] = "thread_send_message_response"
        await sender_websocket.send(json.dumps(message))
        logging.info(f"User {username} sent message to thread {thread_id}")

    async def handle_thread_read_message(self, sender_websocket, message):
        try:
            thread_id = message["thread_id"]
            username = message["username"]
        except:
            logging.error("Invalid thread_read_message: {message}")

        if thread_id not in self.thread_id_to_users:
            message["status"] = "Thread does not exist"
        else:
            message["thread_messages"] = self.thread_id_to_messages[thread_id]
            message["status"] = "Message read successfully"

        message["action"] = "thread_read_message_response"
        await sender_websocket.send(json.dumps(message))
        logging.info(f"User {username} read messages from thread {thread_id}")

    async def message_handler(self, websocket):
        async for message_str in websocket:
            try:
                message = json.loads(message_str)
            except:
                logging.error("Failed to parse message from client:  {message_str}")

            if message["action"] == "key_upload":
                await self.handle_key_upload(websocket, message)
            elif message["action"] == "create_thread":
                await self.handle_thread_create(websocket, message)
            elif message["action"] == "join_thread":
                await self.handle_thread_join(websocket, message)
            elif message["action"] == "leave_thread":
                await self.handle_thread_leave(websocket, message)
            elif message["action"] == "send_message":
                await self.handle_thread_send_message(websocket, message)
            elif message["action"] == "read_message":
                await self.handle_thread_read_message(websocket, message)
            # elif message["action"] == "get_public_key":
            #     await self.handle_get_public_key(websocket, message)

    async def start_server(self, host, port):
        server = await websockets.serve(self.message_handler, host, port)
        await server.wait_closed()


async def main():
    server = ChatServer()
    async with websockets.serve(server.message_handler, "", 8765, ping_interval=None):
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    asyncio.run(main())
