
import hashlib
import random
import numpy as np

from PIL import Image

from .common_crypto import (
    HEADER_BITS,
    create_packet,
    unpack_packet,
)


def bytes_to_bits(data: bytes):
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))


def bits_to_bytes(bits):
    bits = np.asarray(bits, dtype=np.uint8)

    if len(bits) % 8 != 0:
        raise ValueError("Bit count must be divisible by 8.")

    return np.packbits(bits).tobytes()


def get_payload_positions(total_channels, password, salt, method):
    """Return payload positions after reserving header positions."""

    positions = list(range(HEADER_BITS, total_channels))

    if method == "sequential":
        return positions

    if method == "prng":
        seed_material = (
            password.encode("utf-8") + b":data:" + salt
        )

        seed = int.from_bytes(
            hashlib.sha256(seed_material).digest()[:8],
            "big"
        )

        rng = random.Random(seed)
        rng.shuffle(positions)

        return positions

    raise ValueError("Unknown embedding method.")


def embed_image(input_path, output_path, message, password, method):
    """Embed the same encrypted packet using the selected method."""

    image = Image.open(input_path).convert("RGB")
    pixels = np.array(image, dtype=np.uint8)

    flat = pixels.reshape(-1).copy()

    header, encrypted_payload = create_packet(message, password)

    header_bits = bytes_to_bits(header)
    payload_bits = bytes_to_bits(encrypted_payload)

    if len(flat) < HEADER_BITS:
        raise ValueError("Image is too small for the header.")

    positions = get_payload_positions(
        len(flat), password, header[12:28], method
    )

    if len(payload_bits) > len(positions):
        raise ValueError("Payload exceeds image capacity.")

    # Identical header placement for both methods.
    flat[:HEADER_BITS] = (
        (flat[:HEADER_BITS] & 254) | header_bits
    )

    selected = np.asarray(
        positions[:len(payload_bits)],
        dtype=np.int64
    )

    flat[selected] = (
        (flat[selected] & 254) | payload_bits
    )

    stego_pixels = flat.reshape(pixels.shape)

    Image.fromarray(stego_pixels).save(output_path, format="PNG")

    return {
        "payload_bytes": len(encrypted_payload),
        "payload_bits": len(payload_bits),
        "capacity_bits": len(positions),
        "payload_positions": len(selected),
    }


def extract_image(stego_path, password, method):
    """Extract, authenticate and decrypt a hidden message."""

    image = Image.open(stego_path).convert("RGB")
    pixels = np.array(image, dtype=np.uint8)

    flat = pixels.reshape(-1)

    if len(flat) < HEADER_BITS:
        raise ValueError("Image is too small.")

    header_bits = flat[:HEADER_BITS] & 1
    header = bits_to_bytes(header_bits)

    if header[:4] != b"PWP1":
        raise ValueError("No valid PWP header found.")

    payload_length = int.from_bytes(header[8:12], "big")
    payload_bit_length = payload_length * 8

    positions = get_payload_positions(
        len(flat), password, header[12:28], method
    )

    if payload_bit_length > len(positions):
        raise ValueError("Payload length exceeds available capacity.")

    selected = np.asarray(
        positions[:payload_bit_length],
        dtype=np.int64
    )

    payload_bits = flat[selected] & 1
    encrypted_payload = bits_to_bytes(payload_bits)

    return unpack_packet(header, encrypted_payload, password)
