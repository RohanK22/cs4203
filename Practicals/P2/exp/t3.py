import asyncio

import websockets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# Client 1
client1_private_key = ec.generate_private_key(ec.SECP384R1())

# Client 2
client2_private_key = ec.generate_private_key(ec.SECP384R1())

# Client 1 generates shared key
client1_shared_key = b"some shared secret"


client1_public_key = client1_private_key.public_key()
client2_public_key = client2_private_key.public_key()


# Derive shared key
derived_key = client1_private_key.exchange(ec.ECDH(), client2_public_key)

print("Client 1 derived shared key:", derived_key)


# Derive shared key
derived_key = client2_private_key.exchange(ec.ECDH(), client1_public_key)

print("Client 2 derived shared key:", derived_key)


# asyncio.get_event_loop().run_until_complete(asyncio.gather(client1()))


# asyncio.get_event_loop().run_until_complete(asyncio.gather(client2()))
