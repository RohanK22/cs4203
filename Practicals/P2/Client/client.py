import asyncio
import websockets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

import os

from crypto_utils import load_ec_key_pair

# Replace this key with the server's secret key
SECRET_KEY = b"UoJQgRHVAZas_m2TtDJYOIpYf6lbqB6VtCL4BD1_dU0="
cipher_suite = Fernet(SECRET_KEY)


async def hello():
    uri = "ws://localhost:8765"

    ec_keys = load_ec_key_pair()

    async with websockets.connect(uri) as websocket:
        # Send the public key to the server
        public_key_bytes = ec_keys["public_key"].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        await websocket.send(public_key_bytes.decode())
        print(f"> Sent public key: {public_key_bytes.decode()}")

        while True:
            message = input("Type a message to send: ")
            encrypted_message = cipher_suite.encrypt(message.encode()).decode()
            await websocket.send(encrypted_message)
            print(f"> Sent encrypted message: {encrypted_message}")

            encrypted_response = await websocket.recv()
            decrypted_response = cipher_suite.decrypt(
                encrypted_response.encode()
            ).decode()
            print(f"> Received encrypted response: {encrypted_response}")
            print(f"> Decrypted response: {decrypted_response}")


asyncio.get_event_loop().run_until_complete(hello())
