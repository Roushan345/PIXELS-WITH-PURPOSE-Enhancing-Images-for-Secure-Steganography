
import os
import zlib
import hmac
import hashlib

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


MAGIC = b"PWP1"
VERSION = 1
LSB_DEPTH = 1

HEADER_SIZE = 60
HEADER_BITS = HEADER_SIZE * 8


def derive_keys(password: str, salt: bytes):
    """Derive separate AES and HMAC keys from the password."""

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=100_000,
    )

    key_material = kdf.derive(password.encode("utf-8"))

    return key_material[:32], key_material[32:]


def create_packet(message: bytes, password: str):
    """
    Compress and encrypt the payload once.

    Returns the same header and encrypted payload for both algorithms.
    """

    salt = os.urandom(16)
    iv = os.urandom(16)

    aes_key, hmac_key = derive_keys(password, salt)

    compressed = zlib.compress(message, level=9)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(compressed) + padder.finalize()

    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv)
    ).encryptor()

    ciphertext = encryptor.update(padded) + encryptor.finalize()

    encrypted_payload = iv + ciphertext

    mac = hmac.new(
        hmac_key,
        salt + encrypted_payload,
        hashlib.sha256
    ).digest()

    # 4 + 1 + 1 + 2 + 4 + 16 + 32 = 60 bytes
    header = (
        MAGIC
        + bytes([VERSION, LSB_DEPTH])
        + b"\x00\x00"
        + len(encrypted_payload).to_bytes(4, "big")
        + salt
        + mac
    )

    assert len(header) == HEADER_SIZE

    return header, encrypted_payload


def unpack_packet(header: bytes, encrypted_payload: bytes, password: str):
    """Verify, decrypt and decompress an extracted payload."""

    if len(header) != HEADER_SIZE:
        raise ValueError("Invalid header size.")

    if header[:4] != MAGIC:
        raise ValueError("Invalid PWP header.")

    if header[4] != VERSION:
        raise ValueError("Unsupported packet version.")

    if header[5] != LSB_DEPTH:
        raise ValueError("Unsupported LSB depth.")

    expected_length = int.from_bytes(header[8:12], "big")
    salt = header[12:28]
    stored_mac = header[28:60]

    if len(encrypted_payload) != expected_length:
        raise ValueError("Incomplete encrypted payload.")

    aes_key, hmac_key = derive_keys(password, salt)

    calculated_mac = hmac.new(
        hmac_key,
        salt + encrypted_payload,
        hashlib.sha256
    ).digest()

    if not hmac.compare_digest(stored_mac, calculated_mac):
        raise ValueError("HMAC verification failed. Image may be modified.")

    iv = encrypted_payload[:16]
    ciphertext = encrypted_payload[16:]

    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv)
    ).decryptor()

    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    compressed = unpadder.update(padded) + unpadder.finalize()

    return zlib.decompress(compressed)
