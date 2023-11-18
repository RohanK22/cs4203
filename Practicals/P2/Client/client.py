import asyncio
import base64
import json
import logging
import threading

import websockets
from crypto import decrypt_with_key, encrypt_with_key
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from websockets.exceptions import ConnectionClosedOK


class Client:
    def __init__(self):
        self.logger = logging.getLogger("client")
        self.logger.setLevel(logging.INFO)
        self.username = input("Enter your username: ")
        self.ec_private_key = ec.generate_private_key(ec.SECP192R1())
        self.ec_public_key = self.ec_private_key.public_key()
        self.ec_public_key_bytes = self.ec_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.thread_id_to_shared_thread_keys = dict()
        self.websocket = None

        self.in_interactive_mode = False
        self.current_thread_id = None
        self.input_thread_running = False

    async def send_json_message(self, websocket, message):
        await websocket.send(json.dumps(message))

    async def register_user(self, websocket):
        await self.send_json_message(
            websocket,
            {
                "action": "key_upload",
                "username": self.username,
                "public_key": self.ec_public_key_bytes.decode("utf-8"),
            },
        )

    def generate_shared_key_for_new_thread_and_store(self, thread_id):
        fernet_key = Fernet.generate_key()
        self.thread_id_to_shared_thread_keys[thread_id] = fernet_key

    async def interactive_chat_mode(self, thread_id, loop):
        self.in_interactive_mode = True
        self.current_thread_id = thread_id
        self.input_thread_running = True  # Flag to control the input thread
        print("Entering interactive chat mode. Type 'exit' to leave.")

        message_queue = asyncio.Queue()

        def user_input():
            while self.input_thread_running:
                message = input("> ")
                asyncio.run_coroutine_threadsafe(message_queue.put(message), loop)

        input_thread = threading.Thread(target=user_input, daemon=True)
        input_thread.start()

        while self.in_interactive_mode:
            message = await message_queue.get()

            if message.lower() == "exit":
                self.in_interactive_mode = False
                self.current_thread_id = None
                self.input_thread_running = False  # Signal the input thread to stop
                print("Exiting interactive chat mode.")
                break

            thread_key = self.thread_id_to_shared_thread_keys.get(thread_id)
            if thread_key:
                fernet = Fernet(thread_key)
                encrypted_message = fernet.encrypt(message.encode("utf-8")).decode(
                    "utf-8"
                )
                await self.send_json_message(
                    self.websocket,
                    {
                        "action": "send_message",
                        "thread_id": thread_id,
                        "username": self.username,
                        "message": encrypted_message,
                    },
                )

        input_thread.join()  # Wait for the input thread to finish

    async def send_thread(self, websocket):
        loop = asyncio.get_running_loop()
        while True:
            await asyncio.sleep(1)
            action = await self.get_user_action(loop)
            if action == "exit":
                break
            await self.handle_action(websocket, action, loop)

    async def get_user_action(self, loop):
        menu_options = "Pick option:\n" + "\n".join(
            [
                "1. Create Thread",
                "2. Join Thread",
                "3. Leave Thread",
                "4. Send Message",
                "5. Read Message",
                "6. Interactive Chat Mode",
                "7. Exit",
            ]
        )
        print(menu_options)
        return await loop.run_in_executor(None, input, "Enter action: ")

    async def handle_action(self, websocket, action, loop):
        if action == "1":  # Create Thread
            thread_id = input("Enter thread id: ")
            await self.send_json_message(
                websocket,
                {
                    "action": "create_thread",
                    "thread_id": thread_id,
                    "username": self.username,
                },
            )
            self.generate_shared_key_for_new_thread_and_store(thread_id)

        elif action == "2":  # Join Thread
            thread_id = input("Enter thread id: ")
            await self.send_json_message(
                websocket,
                {
                    "action": "join_thread",
                    "thread_id": thread_id,
                    "username": self.username,
                },
            )
            # Optionally, handle the server's response here

            if thread_id not in self.thread_id_to_shared_thread_keys:
                await self.send_json_message(
                    websocket,
                    {
                        "action": "thread_key_request",
                        "thread_id": thread_id,
                        "username": self.username,
                    },
                )

        elif action == "3":  # Leave Thread
            thread_id = input("Enter thread id: ")
            await self.send_json_message(
                websocket,
                {
                    "action": "leave_thread",
                    "thread_id": thread_id,
                    "username": self.username,
                },
            )

        elif action == "4":  # Send Message
            thread_id = input("Enter thread id: ")
            message = input("Enter message: ")
            thread_key = self.thread_id_to_shared_thread_keys.get(thread_id)
            if thread_key:
                fernet = Fernet(thread_key)
                encrypted_message = fernet.encrypt(message.encode("utf-8")).decode(
                    "utf-8"
                )
                await self.send_json_message(
                    websocket,
                    {
                        "action": "send_message",
                        "thread_id": thread_id,
                        "username": self.username,
                        "message": encrypted_message,
                    },
                )
            else:
                print("You do not have the key for this thread.")

        elif action == "5":  # Read Message
            thread_id = input("Enter thread id: ")
            await self.send_json_message(
                websocket,
                {
                    "action": "read_message",
                    "thread_id": thread_id,
                    "username": self.username,
                },
            )

        elif action == "6":  # Interactive Chat Mode
            thread_id = input("Enter thread id for interactive chat: ")
            await asyncio.create_task(self.interactive_chat_mode(thread_id, loop))

        elif action == "7":
            print("Exiting...")
            # close the connection
            await websocket.close()
            exit(0)

    async def receive_thread(self, websocket):
        while True:
            try:
                message = await websocket.recv()
                message = json.loads(message)
            except ConnectionClosedOK:
                self.logger.error("Server disconnected.")
            except json.JSONDecodeError:
                self.logger.exception("Failed to parse message from server.")
            except Exception as e:
                self.logger.exception("Fatal Error: ", e)

            if "action" not in message:
                continue

            if message["action"] == "thread_key_request":
                await self.handle_thread_key_request(websocket, message)
            elif message["action"] == "thread_key_response":
                await self.handle_thread_key_response(message)
            elif message["action"] == "thread_read_message_response":
                await self.handle_thread_read_message_response(message)
            elif (
                self.in_interactive_mode
                and "action" in message
                and message["action"] == "new_message"
                and message["thread_id"] == self.current_thread_id
            ):
                encrypted_message = message["message"]
                thread_key = self.thread_id_to_shared_thread_keys.get(
                    self.current_thread_id
                )
                if thread_key:
                    fernet = Fernet(thread_key)
                    decrypted_message = fernet.decrypt(
                        encrypted_message.encode("utf-8")
                    ).decode("utf-8")
                    print(
                        f"\n{message['sender']}: {decrypted_message}\n> ",
                        end="",
                        flush=True,
                    )
            else:
                action = message["action"] if "action" in message else None
                thread_id = message["thread_id"] if "thread_id" in message else None
                status = message["status"] if "status" in message else None

                print(
                    f"Received message from server: \n response_type: {action} \n thread_id: {thread_id} \n status: {status}"
                )

    async def handle_thread_key_request(self, websocket, message):
        thread_id = message["thread_id"]
        requestor_public_key = serialization.load_pem_public_key(
            message["requestor_public_key"].encode("utf-8")
        )
        requestor_username = message["username"]
        thread_key = self.thread_id_to_shared_thread_keys[thread_id]

        # ECDH
        ec_shared_secret = self.ec_private_key.exchange(ec.ECDH(), requestor_public_key)

        # Encrypt thread key
        thread_key_cipher = encrypt_with_key(thread_key, ec_shared_secret)

        # Sign thread key
        signature = self.ec_private_key.sign(
            thread_key_cipher, ec.ECDSA(hashes.SHA256())
        )

        await self.send_json_message(
            websocket,
            {
                "action": "thread_key_response",
                "thread_id": thread_id,
                "thread_key_cipher": base64.b64encode(thread_key_cipher).decode(
                    "utf-8"
                ),
                "signature": base64.b64encode(signature).decode("utf-8"),
                "username": requestor_username,
                "responder_username": self.username,
                "responder_public_key": self.ec_public_key_bytes.decode("utf-8"),
            },
        )

    async def handle_thread_key_response(self, message):
        thread_id = message["thread_id"]
        thread_key_cipher = base64.b64decode(
            message["thread_key_cipher"].encode("utf-8")
        )
        signature = base64.b64decode(message["signature"].encode("utf-8"))
        responder_public_key = serialization.load_pem_public_key(
            message["responder_public_key"].encode("utf-8")
        )

        # Compute shared key
        ec_shared_secret = self.ec_private_key.exchange(ec.ECDH(), responder_public_key)

        # Verify signature
        responder_public_key.verify(
            signature, thread_key_cipher, ec.ECDSA(hashes.SHA256())
        )

        # Decrypt thread key
        thread_key = decrypt_with_key(thread_key_cipher, ec_shared_secret)
        self.thread_id_to_shared_thread_keys[thread_id] = thread_key

        print(f"Thread key received for thread {thread_id}")

    async def handle_thread_read_message_response(self, message):
        thread_id = message["thread_id"]
        thread_messages = message["thread_messages"]

        if thread_id not in self.thread_id_to_shared_thread_keys:
            print("No key available for this thread.")
            return

        thread_key = self.thread_id_to_shared_thread_keys[thread_id]
        fernet = Fernet(thread_key)

        for sender, encrypted_message in thread_messages:
            decrypted_message = fernet.decrypt(
                encrypted_message.encode("utf-8")
            ).decode("utf-8")
            print(f"{sender}: {decrypted_message}")

    async def full_duplex_handler(self, websocket):
        receiving_task = asyncio.create_task(self.receive_thread(websocket))
        sending_task = asyncio.create_task(self.send_thread(websocket))
        await asyncio.gather(sending_task, receiving_task)

    async def start_client(self):
        async with websockets.connect(
            "ws://localhost:8765", ping_interval=None
        ) as websocket:
            self.websocket = websocket
            await self.register_user(websocket)
            await self.full_duplex_handler(websocket)


if __name__ == "__main__":
    client = None
    try:
        client = Client()
        asyncio.run(client.start_client())
    except KeyboardInterrupt:
        print("Exiting...")
    except ConnectionClosedOK:
        print("Closed connection with server.")
    except Exception as e:
        client.logger.exception(e)
        print("Failed to connect to server.")
    finally:
        if client.websocket:
            client.websocket.close()
