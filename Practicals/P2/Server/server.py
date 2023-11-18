import asyncio
import json
import logging

import websockets

logging.basicConfig(level=logging.INFO)


class ChatServer:
    def __init__(self):
        self.user_public_key = dict()
        self.user_socket = dict()

        self.thread_id_to_users = dict()
        self.thread_id_to_messages = dict()
        self.thread_id_to_creator = dict()

        self.logger = logging.getLogger("ChatServer")
        self.logger.setLevel(logging.INFO)

        self.websocket = None

    # Save public key for user
    async def handle_key_upload(self, sender_websocket, message):
        try:
            username = message["username"]
            public_key = message["public_key"]
        except:
            logging.error(f"Invalid key_upload message: {message}")

        self.user_public_key[username] = public_key
        self.user_socket[username] = sender_websocket

        message["action"] = "key_upload_response"
        message["status"] = "Registered successfully"
        await sender_websocket.send(json.dumps(message))
        logging.info(f"User registered: {username}")

    # Create a thread
    async def handle_thread_create(self, sender_websocket, message):
        # TODO: Check if user exists / registered
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
        await sender_websocket.send(json.dumps(message))
        logging.info(f"Created thread {thread_id}")

    # Join a thread
    async def handle_thread_join(self, sender_websocket, message):
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

    async def broadcast_message_to_thread(self, thread_id, message, sender_username):
        if thread_id in self.thread_id_to_users:
            participants = self.thread_id_to_users[thread_id]
            for participant in participants:
                if participant == sender_username:
                    continue
                try:
                    await self.user_socket[participant].send(json.dumps(message))
                except Exception as e:
                    self.logger.error(
                        f"Error broadcasting message to {participant}: {e}"
                    )

    # Send a message to a thread
    async def handle_thread_send_message(self, sender_websocket, message):
        try:
            thread_id = message["thread_id"]
            username = message["username"]
            message_content = message["message"]
        except:
            logging.error("Invalid thread_send_message: {message}")

        logging.info(
            f"Received message from {username} to thread {thread_id}. Message: {message_content}"
        )

        if thread_id not in self.thread_id_to_users:
            message["status"] = "Thread does not exist"
        else:
            self.thread_id_to_messages[thread_id].append((username, message_content))
            message["status"] = "Message sent successfully"

            broadcast_message = {
                "action": "new_message",
                "thread_id": thread_id,
                "sender": username,
                "message": message_content,
            }
            await self.broadcast_message_to_thread(
                thread_id, broadcast_message, username
            )

        message["action"] = "thread_send_message_response"
        await sender_websocket.send(json.dumps(message))
        logging.info(f"User {username} sent message to thread {thread_id}")

    # Retrieve messages that belongs to a thread
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

    async def handle_get_public_key(self, sender_websocket, message):
        try:
            username = message["username"]
            target_username = message["target_username"]
        except:
            logging.error("Invalid get_public_key: {message}")

        if target_username not in self.user_public_key:
            message["status"] = "User does not exist"
        else:
            message["public_key"] = self.user_public_key[target_username]
            message["status"] = "Public key retrieved successfully"

        message["action"] = "get_public_key_response"
        await sender_websocket.send(json.dumps(message))
        logging.info(f"User {username} retrieved public key for {target_username}")

    async def handle_get_thread_creator(self, sender_websocket, message):
        try:
            thread_id = message["thread_id"]
            username = message["username"]
        except:
            logging.error("Invalid get_thread_creator: {message}")

        if thread_id not in self.thread_id_to_users:
            message["status"] = "Thread does not exist"
        else:
            message["thread_creator"] = self.thread_id_to_creator[thread_id]
            message["status"] = "Thread creator retrieved successfully"

        message["action"] = "get_thread_creator_response"
        await sender_websocket.send(json.dumps(message))
        logging.info(f"User {username} retrieved thread creator for {thread_id}")

    async def handle_thread_key_request(self, sender_websocket, message):
        try:
            thread_id = message["thread_id"]
            username = message["username"]
        except:
            logging.error("Invalid get_thread_creator: {message}")
            return

        # send this message to creator
        if thread_id not in self.thread_id_to_users:
            message["status"] = "Thread does not exist"
        else:
            thread_creator_username = self.thread_id_to_creator[thread_id]
            thread_creator_socket = self.user_socket[thread_creator_username]

            logging.info(f"Sending thread key request to {thread_creator_username}")

            requestor_public_key = self.user_public_key[username]
            message["requestor_public_key"] = requestor_public_key

            message = json.dumps(message)

            await thread_creator_socket.send(message)
        # logging.info(f"User {username} retrieved thread creator for {thread_id}")

    async def handle_thread_key_response(self, sender_websocket, message):
        try:
            thread_id = message["thread_id"]
            username = message["username"]
            responder_username = message["responder_username"]
        except:
            logging.error("Invalid get_thread_creator: {message}")
            return

        logging.info(f"Received thread key response from {responder_username}")

        # get user websocket
        user_socket = self.user_socket[username]
        message["responder_public_key"] = self.user_public_key[responder_username]

        message = json.dumps(message)

        await user_socket.send(message)

    async def message_handler(self, websocket):
        self.websocket = websocket
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
            elif message["action"] == "get_public_key":
                await self.handle_get_public_key(websocket, message)
            elif message["action"] == "get_thread_creator":
                await self.handle_get_thread_creator(websocket, message)
            elif message["action"] == "thread_key_request":
                await self.handle_thread_key_request(websocket, message)
            elif message["action"] == "thread_key_response":
                await self.handle_thread_key_response(websocket, message)

    async def start_server(self, host, port):
        server = await websockets.serve(self.message_handler, host, port)
        await server.wait_closed()


async def main(server):
    async with websockets.serve(server.message_handler, "", 8765, ping_interval=None):
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    try:
        server = ChatServer()
        asyncio.run(main(server))
    except KeyboardInterrupt:
        print("Exiting...")
    except Exception as e:
        print(e)
    finally:
        if server.websocket.open:
            server.websocket.close()
