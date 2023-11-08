import asyncio
import base64
import json
import threading

import websockets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

username = input("Enter your username: ")
ec_private_key = ec.generate_private_key(ec.SECP192R1())
ec_public_key = ec_private_key.public_key()

ec_public_key_bytes = ec_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

# Can make this persist
thread_id_to_shared_thread_keys = dict()

print("Public key generated: {ec_public_key_bytes}")


# Send our public key to server
async def register_user(websocket):
    await websocket.send(
        json.dumps(
            {
                "action": "key_upload",
                "username": username,
                "public_key": ec_public_key_bytes.decode("utf-8"),
            }
        )
    )
    # TODO: Check


def generate_shared_key_for_new_thread_and_store(thread_id):
    fernet_key = Fernet.generate_key()
    thread_id_to_shared_thread_keys[thread_id] = fernet_key


async def send_thread(websocket):
    # Prevent locking of resource - https://stackoverflow.com/questions/74990979/python-websockets-sends-messages-but-cannot-receive-messages-asynchronously

    loop = asyncio.get_running_loop()
    while True:
        await asyncio.sleep(1)
        action = await loop.run_in_executor(
            None,
            input,
            "Enter action (create_thread, join_thread, leave_thread, send_message, read_message, exit): ",
        )

        if action == "exit":
            break

        if action == "1":
            thread_id = input("Enter thread id: ")
            await websocket.send(
                json.dumps(
                    {
                        "action": "create_thread",
                        "thread_id": thread_id,
                        "username": username,
                    }
                )
            )
            generate_shared_key_for_new_thread_and_store(thread_id)
        elif action == "2":
            thread_id = input("Enter thread id: ")
            await websocket.send(
                json.dumps(
                    {
                        "action": "join_thread",
                        "thread_id": thread_id,
                        "username": username,
                    }
                )
            )

            # TODO: Check response

            if thread_id in thread_id_to_shared_thread_keys:
                print("Already in group. ready to chat")
                continue
            await websocket.send(
                json.dumps(
                    {
                        "action": "thread_key_request",
                        "thread_id": thread_id,
                        "username": username,
                    }
                )
            )
        elif action == "3":
            thread_id = input("Enter thread id: ")
            await websocket.send(
                json.dumps(
                    {
                        "action": "leave_thread",
                        "thread_id": thread_id,
                        "username": username,
                    }
                )
            )
        elif action == "4":
            thread_id = input("Enter thread id: ")
            message = input("Enter message: ")

            # Encrypt message with thread key
            thread_key = thread_id_to_shared_thread_keys[thread_id]
            fernet = Fernet(thread_key)
            message = fernet.encrypt(message.encode("utf-8")).decode("utf-8")

            await websocket.send(
                json.dumps(
                    {
                        "action": "send_message",
                        "thread_id": thread_id,
                        "username": username,
                        "message": message,
                    }
                )
            )
        elif action == "5":
            thread_id = input("Enter thread id: ")

            await websocket.send(
                json.dumps(
                    {
                        "action": "read_message",
                        "thread_id": thread_id,
                        "username": username,
                    }
                )
            )
        else:
            print("Invalid action")


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt_with_key(raw, key):
    # Use the key for encryption
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    # Apply padding to the raw data
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(raw) + padder.finalize()

    # Encrypt the padded data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ciphertext


def decrypt_with_key(cipher_text, key):
    # Use the key for decryption
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    decrypted_padded_data = decryptor.update(cipher_text) + decryptor.finalize()

    # Remove the padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_data


async def receive_thread(websocket):
    while True:
        message = await websocket.recv()
        message = json.loads(message)
        print(f"Received message: {message}")

        if "action" in message and message["action"] == "thread_key_request":
            thread_id = message["thread_id"]
            requestor_public_key = message["requestor_public_key"]
            requestor_public_key = serialization.load_pem_public_key(
                requestor_public_key.encode("utf-8")
            )
            requestor_username = message["username"]

            thread_key = thread_id_to_shared_thread_keys[thread_id]

            print("thread_key:", thread_key)

            # ECDH
            derived_key = ec_private_key.exchange(ec.ECDH(), requestor_public_key)

            # encrypt thread key
            thread_key_cipher = encrypt_with_key(thread_key, derived_key)

            # sign thread key
            signature = ec_private_key.sign(
                thread_key_cipher,
                ec.ECDSA(hashes.SHA256()),
            )

            print("derivedkey:", derived_key)
            print("thread_key_cipher:", thread_key_cipher)
            print("signature:", signature)

            await websocket.send(
                json.dumps(
                    {
                        "action": "thread_key_response",
                        "thread_id": thread_id,
                        "thread_key_cipher": base64.b64encode(thread_key_cipher).decode(
                            "utf-8"
                        ),
                        "signature": base64.b64encode(signature).decode("utf-8"),
                        "username": requestor_username,
                        "responder_username": username,
                        "responder_public_key": ec_public_key_bytes.decode("utf-8"),
                    }
                )
            )
        if "action" in message and message["action"] == "thread_key_response":
            thread_id = message["thread_id"]
            thread_key_cipher = base64.b64decode(
                message["thread_key_cipher"].encode("utf-8")
            )
            signature = base64.b64decode(message["signature"].encode("utf-8"))
            responder_public_key = message["responder_public_key"]
            responder_public_key = serialization.load_pem_public_key(
                responder_public_key.encode("utf-8")
            )

            # Compute shared key
            derived_key = ec_private_key.exchange(ec.ECDH(), responder_public_key)

            print("derivedkey:", derived_key)
            print("thread_key_cipher:", thread_key_cipher)
            print("signature:", signature)

            # Verify signature
            responder_public_key.verify(
                signature,
                thread_key_cipher,
                ec.ECDSA(hashes.SHA256()),
            )

            # Decrypt thread key
            thread_key = decrypt_with_key(thread_key_cipher, derived_key)

            thread_id_to_shared_thread_keys[thread_id] = thread_key

            print(f"Thread key received {thread_key}")

        if "action" in message and message["action"] == "thread_read_message_response":
            thread_id = message["thread_id"]
            thread_messages = message["thread_messages"]

            # Decrypt messages
            thread_key = thread_id_to_shared_thread_keys[thread_id]
            fernet = Fernet(thread_key)

            print(thread_messages)

            for sender, message in thread_messages:
                print(
                    f"{sender}: {fernet.decrypt(message.encode('utf-8')).decode('utf-8')}"
                )


# Define the main function
async def full_duplex_handler(websocket):
    receiving_task = asyncio.create_task(receive_thread(websocket))
    sending_task = asyncio.create_task(send_thread(websocket))

    await asyncio.gather(sending_task, receiving_task)


async def start_client():
    async with websockets.connect(
        "ws://localhost:8765", ping_interval=None
    ) as websocket:
        await register_user(websocket)
        await full_duplex_handler(websocket)


if __name__ == "__main__":
    asyncio.run(start_client())
