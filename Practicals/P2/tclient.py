import asyncio
import base64
import json
import threading

import socketio
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# Initialize the Socket.IO client
sio = socketio.Client()

# Input username
username = input("Enter your username: ")

# Generate EC key pair
ec_private_key = ec.generate_private_key(ec.SECP192R1())
ec_public_key = ec_private_key.public_key()

ec_public_key_bytes = ec_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

# Can make this persist
thread_id_to_shared_thread_keys = dict()

print("Public key generated:", ec_public_key_bytes.decode("utf-8"))


# Send our public key to the server
@sio.event
async def connect():
    await sio.emit(
        "key_upload",
        {
            "username": username,
            "public_key": ec_public_key_bytes.decode("utf-8"),
        },
    )


# Handle disconnect event
@sio.event
def disconnect():
    print("Disconnected from the server.")


# Generate and store shared key for a new thread
def generate_shared_key_for_new_thread_and_store(thread_id):
    fernet_key = Fernet.generate_key()
    thread_id_to_shared_thread_keys[thread_id] = fernet_key


# Send messages to the server
async def send_thread():
    while True:
        action = input(
            "Enter action (create_thread, join_thread, leave_thread, send_message, read_message, exit): "
        )

        if action == "exit":
            break

        if action == "create_thread":
            thread_id = input("Enter thread id: ")
            await sio.emit(
                "create_thread",
                {
                    "thread_id": thread_id,
                    "username": username,
                },
            )
            generate_shared_key_for_new_thread_and_store(thread_id)
        elif action == "join_thread":
            thread_id = input("Enter thread id: ")
            await sio.emit(
                "join_thread",
                {
                    "thread_id": thread_id,
                    "username": username,
                },
            )

            if thread_id in thread_id_to_shared_thread_keys:
                print("Already in group. Ready to chat.")
                continue
            await sio.emit(
                "thread_key_request",
                {
                    "thread_id": thread_id,
                    "username": username,
                },
            )
        elif action == "leave_thread":
            thread_id = input("Enter thread id: ")
            await sio.emit(
                "leave_thread",
                {
                    "thread_id": thread_id,
                    "username": username,
                },
            )
        elif action == "send_message":
            thread_id = input("Enter thread id: ")
            message = input("Enter message: ")

            # Encrypt message with thread key
            thread_key = thread_id_to_shared_thread_keys[thread_id]
            fernet = Fernet(thread_key)
            message = fernet.encrypt(message.encode("utf-8")).decode("utf-8")

            await sio.emit(
                "send_message",
                {
                    "thread_id": thread_id,
                    "username": username,
                    "message": message,
                },
            )
        elif action == "read_message":
            thread_id = input("Enter thread id: ")
            await sio.emit(
                "read_message",
                {
                    "thread_id": thread_id,
                    "username": username,
                },
            )
        else:
            print("Invalid action")


# Encrypt data with a key
def encrypt_with_key(raw, key):
    cipher = Fernet(key)
    encrypted_data = cipher.encrypt(raw.encode("utf-8"))
    return encrypted_data


# Decrypt data with a key
def decrypt_with_key(encrypted_data, key):
    cipher = Fernet(key)
    decrypted_data = cipher.decrypt(encrypted_data).decode("utf-8")
    return decrypted_data


# Receive and process messages from the server
@sio.on("message")
async def receive_message(message):
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

        # Perform ECDH to derive a shared key
        derived_key = ec_private_key.exchange(ec.ECDH(), requestor_public_key)

        # Encrypt the thread key
        thread_key_cipher = encrypt_with_key(thread_key, derived_key)

        # Sign the encrypted thread key
        signature = ec_private_key.sign(
            thread_key_cipher,
            ec.ECDSA(hashes.SHA256()),
        )

        await sio.emit(
            "thread_key_response",
            {
                "thread_id": thread_id,
                "thread_key_cipher": base64.b64encode(thread_key_cipher).decode(
                    "utf-8"
                ),
                "signature": base64.b64encode(signature).decode("utf-8"),
                "username": requestor_username,
                "responder_username": username,
                "responder_public_key": ec_public_key_bytes.decode("utf-8"),
            },
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

        # Compute the shared key
        derived_key = ec_private_key.exchange(ec.ECDH(), responder_public_key)

        # Verify the signature
        responder_public_key.verify(
            signature,
            thread_key_cipher,
            ec.ECDSA(hashes.SHA256()),
        )

        # Decrypt the thread key
        thread_key = decrypt_with_key(thread_key_cipher, derived_key)

        thread_id_to_shared_thread_keys[thread_id] = thread_key

        print(f"Thread key received: {thread_key}")


if __name__ == "__main__":
    with socketio.SimpleClient() as client:
        client.connect("http://localhost:8765")
        client.start_background_task(send_thread)
