import asyncio

import websockets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# Generate key pairs
client1_private_key = ec.generate_private_key(ec.SECP384R1())
client2_private_key = ec.generate_private_key(ec.SECP384R1())

# Client 1 generates shared key
client1_shared_key = (
    ec.generate_private_key(ec.SECP384R1()).private_numbers().private_value
)


async def client1():
    async with websockets.connect("ws://localhost:8765") as ws:
        # Serialize public key
        client1_public_key = client1_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Send serialized public key
        await ws.send(client1_public_key)

        # Receive serialized public key
        client2_public_key_bytes = await ws.recv()

        # Deserialize public key
        client2_public_key = serialization.load_pem_public_key(client2_public_key_bytes)

        # Derive shared key
        derived_key = client1_private_key.exchange(ec.ECDH(), client2_public_key)

        print("Client 1 derived shared key:", derived_key)


async def client2():
    async with websockets.connect("ws://localhost:8765") as ws:
        # Receive serialized public key
        client1_public_key_bytes = await ws.recv()

        # Deserialize public key
        client1_public_key = serialization.load_pem_public_key(client1_public_key_bytes)

        # Serialize public key
        client2_public_key = client2_private_key.public_key().public_bytes(...)

        # Send serialized public key
        await ws.send(client2_public_key)

        # Derive shared key
        derived_key = client2_private_key.exchange(ec.ECDH(), client1_public_key)

        print("Client 2 derived shared key:", derived_key)


asyncio.get_event_loop().run_until_complete(asyncio.gather(client1(), client2()))
