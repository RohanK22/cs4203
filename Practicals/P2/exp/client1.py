import asyncio

import websockets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


async def client1():
    async with websockets.connect("ws://localhost:8765") as ws:
        # Generate keys
        client1_private_key = ec.generate_private_key(ec.SECP384R1())
        client1_shared_key = (
            ec.generate_private_key(ec.SECP384R1()).private_numbers().private_value
        )

        pk = client1_private_key.public_key()

        # Send public key
        await ws.send(
            pk.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

        # Receive client 2 public key
        client2_public_key_bytes = await ws.recv()
        client2_public_key = serialization.load_pem_public_key(client2_public_key_bytes)

        # Derive shared key
        derived_key = client1_private_key.exchange(ec.ECDH(), client2_public_key)

        print("Client 1 derived shared key:", derived_key)


if __name__ == "__main__":
    asyncio.run(client1())
