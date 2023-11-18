from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# Based on AES block cipher standardised by NIST
# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
def encrypt_with_key(raw: bytes, ec_shared_secret: bytes):
    # Create a cipher from shared EC secret
    cipher = Cipher(
        algorithms.AES(ec_shared_secret), modes.ECB(), backend=default_backend()
    )
    encryptor = cipher.encryptor()

    # Apply padding to the raw data because AES is a block cipher
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(raw) + padder.finalize()

    # Encrypt the padded data
    cipherbytes = encryptor.update(padded_data) + encryptor.finalize()

    return cipherbytes


def decrypt_with_key(cipher_bytes: bytes, ec_shared_secret: bytes):
    # Create a cipher from shared EC secret
    cipher = Cipher(
        algorithms.AES(ec_shared_secret), modes.ECB(), backend=default_backend()
    )
    decryptor = cipher.decryptor()

    # Decrypt the cipherbytes
    decrypted_padded_data = decryptor.update(cipher_bytes) + decryptor.finalize()

    # Remove the padding from the decrypted data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_bytes = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_bytes
