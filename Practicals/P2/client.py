import asyncio
import json

import websockets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
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

    response = await websocket.recv()
    print("Response from server: {response}")
    # TODO: Check


# Retrieve public key of another user from server
async def get_public_key(websocket, username, target_username):
    await websocket.send(
        json.dump(
            {
                "action": "get_public_key",
                "username": username,
                "target_username": target_username,
            }
        )
    )

    response = await websocket.recv()
    print("Response from server: {response}")
    response = json.loads(response)

    if response["status"] == "Public key retrieved successfully":
        return response["public_key"]
    else:
        raise Exception("Failed to retrieve public key: " + response["status"])


async def get_thread_creator(websocket, username, thread_id):
    await websocket.send(
        json.dump(
            {
                "action": "get_thread_creator",
                "username": username,
                "thread_id": thread_id,
            }
        )
    )

    response = await websocket.recv()
    print("Response from server: {response}")
    response = json.loads(response)

    if response["status"] == "Thread creator retrieved successfully":
        return response["thread_creator"]
    else:
        raise Exception("Failed to retrieve thread creator: " + response["status"])


def generate_shared_key_for_new_thread_and_store(thread_id):
    fernet_key = Fernet.generate_key()
    thread_id_to_shared_thread_keys[thread_id] = fernet_key


async def start_client():
    async with websockets.connect(
        "ws://localhost:8765", ping_interval=None
    ) as websocket:
        # attach event listener

        await register_user(websocket)
        while True:
            action = input(
                "Enter action (create_thread, join_thread, leave_thread, send_message, read_message, exit)"
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
                response = await websocket.recv()
                print(f"Response from server: {response})")

                # TODO: Check response
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
                response = await websocket.recv()
                print(f"Response from server: {response})")

                # TODO: Check response

                if thread_id in thread_id_to_shared_thread_keys:
                    print("Already in group. ready to chat")
                    continue

                # Perform a ECDH to request shared key
                thread_creator = await get_thread_creator(
                    websocket, username, thread_id
                )
                thread_creator_public_key = await get_public_key(
                    websocket, username, thread_creator
                )

                thread_creator_public_key = serialization.load_pem_public_key(
                    thread_creator_public_key
                )

                shared_ec_key = ec_private_key.exchange(
                    ec.ECDH(), thread_creator_public_key
                )

                thread_key = thread_id_to_shared_thread_keys[thread_id]

                # garble thread key using shared_ec_key and send to server
                fernet_key = Fernet(shared_ec_key)

                # encrypt
                thread_key_encrypted = fernet_key.encrypt(thread_key)

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
                response = await websocket.recv()
                print(f"Response from server: {response})")
            elif action == "4":
                thread_id = input("Enter thread id: ")
                message = input("Enter message: ")

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
                response = await websocket.recv()
                print(f"Response from server: {response})")
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

                response = await websocket.recv()
                print(f"Response from server: {response})")
                response = json.loads(response)

                for sender, message in response["thread_messages"]:
                    print(f"{sender}: {message}")
            else:
                print("Invalid action")


if __name__ == "__main__":
    asyncio.run(start_client())
