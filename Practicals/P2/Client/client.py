import asyncio
import os

import websockets
from crypto_utils import load_ec_key_pair
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from Message import Message, MessageType, decode_json, encode_json

# Replace this key with the server's secret key
SECRET_KEY = b"UoJQgRHVAZas_m2TtDJYOIpYf6lbqB6VtCL4BD1_dU0="
cipher_suite = Fernet(SECRET_KEY)


async def hello():
    uri = "ws://localhost:8765"

    ec_keys = load_ec_key_pair()

    async with websockets.connect(uri) as websocket:
        # Send register message to server
        public_key_bytes = ec_keys["public_key"].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        m = Message(
            "REGISTER",
            {"username": "alice", "public_key": public_key_bytes.decode()},
        )

        print(encode_json(m))
        await websocket.send(encode_json(m))
        print(f"> Sent public key: {public_key_bytes.decode()}")

        # Receive response from server
        response = await websocket.recv()
        print(f"> Received response: {response}")
        response = decode_json(response)

        messageMode = False
        messageHistory = []

        # TODO: Check if registration was successful
        while True:
            if not messageMode:
                print("Pick an option: ")
                print("1. Create thread")
                print("2. Join thread")
                print("3. Leave thread")
                print("4. Get threads")
                print("5. Enter Message Mode")

                option = input("Select an option: ")

                if option == "1":
                    thread_id = input("Enter thread id: ")
                    m = Message(
                        "CREATE_THREAD",
                        {"thread_id": thread_id, "sender": "alice"},
                    )
                    await websocket.send(encode_json(m))
                    response = await websocket.recv()
                    print(f"> Received response: {response}")
                    response = decode_json(response)

                    # Create shared Fernet secret and store in local state

                    # generate 32 byte shared secret
                    shared_secret = Fernet.generate_key()

                    print(shared_secret)

                elif option == "2":
                    thread_id = input("Enter thread id: ")
                    m = Message(
                        MessageType.JOIN_THREAD,
                        {"thread_id": thread_id, "sender": "alice"},
                    )
                    await websocket.send(encode_json(m))
                    response = await websocket.recv()
                    print(f"> Received response: {response}")
                    response = decode_json(response)
                elif option == "3":
                    thread_id = input("Enter thread id: ")
                    m = Message(
                        MessageType.LEAVE_THREAD,
                        {"thread_id": thread_id, "sender": "alice"},
                    )
                    await websocket.send(encode_json(m))
                    response = await websocket.recv()
                    print(f"> Received response: {response}")
                    response = decode_json(response)
                elif option == "4":
                    m = Message(MessageType.GET_THREADS, {"sender": "alice"})
                    await websocket.send(encode_json(m))
                    response = await websocket.recv()
                    print(f"> Received response: {response}")
                    response = decode_json(response)
                    # print out threads
                elif option == "5":
                    # fetch messages from thread
                    thread_id = input("Enter thread id: ")
                    m = Message(
                        MessageType.GET_MESSAGES,
                        {"thread_id": thread_id, "sender": "alice"},
                    )
                    await websocket.send(encode_json(m))
                    response = await websocket.recv()
                    print(f"> Received response: {response}")
                    response = decode_json(response)
                    messageMode = True
                    messageHistory = response.data["messages"]
                    print(messageHistory)

                    # do ECDH with owner of thread to get shared secret

                    response = await websocket.recv()
            else:
                print("You are in message mode")

            # encrypted_message = cipher_suite.encrypt(message.encode()).decode()
            # await websocket.send(encrypted_message)
            # print(f"> Sent encrypted message: {encrypted_message}")

            # encrypted_response = await websocket.recv()
            # decrypted_response = cipher_suite.decrypt(
            #     encrypted_response.encode()
            # ).decode()
            # print(f"> Received encrypted response: {encrypted_response}")
            # print(f"> Decrypted response: {decrypted_response}")


asyncio.get_event_loop().run_until_complete(hello())
