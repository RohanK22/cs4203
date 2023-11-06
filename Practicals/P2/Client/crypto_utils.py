import asyncio
import websockets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import os


def load_ec_key_pair():
    ec_keys = {"private_key": None, "public_key": None}
    keys_folder = os.path.join(os.path.dirname(__file__), "keys")
    if not os.path.exists(keys_folder):
        os.makedirs(keys_folder)

    private_key_path = os.path.join(keys_folder, "private_key.pem")
    public_key_path = os.path.join(keys_folder, "public_key.pem")

    if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
        print("Generating EC keys...")

        ec_keys["private_key"] = ec.generate_private_key(ec.SECP384R1())
        ec_keys["public_key"] = ec_keys["private_key"].public_key()

        with open(private_key_path, "wb") as f:
            f.write(
                ec_keys["private_key"].private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        with open(public_key_path, "wb") as f:
            f.write(
                ec_keys["public_key"].public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
    else:
        print("Loading EC keys...")
        with open(private_key_path, "rb") as f:
            ec_keys["private_key"] = serialization.load_pem_private_key(
                f.read(), password=None
            )

        with open(public_key_path, "rb") as f:
            ec_keys["public_key"] = serialization.load_pem_public_key(f.read())

    print("EC keys loaded.")
    return ec_keys
