import asyncio

import websockets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


async def client2():
    async with websockets.connect("ws://localhost:8765") as ws:
        # Generate keys
        client2_private_key = ec.generate_private_key(ec.SECP384R1())

        # Receive client 1 public key
        client1_public_key_bytes = await ws.recv()
        client1_public_key = serialization.load_der_public_key(client1_public_key_bytes)

        # Send public key
        await ws.send(
            client2_private_key.public_key(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

        # Derive shared key
        derived_key = client2_private_key.exchange(ec.ECDH(), client1_public_key)

        print("Client 2 derived shared key:", derived_key)


if __name__ == "__main__":
    asyncio.run(client2())
