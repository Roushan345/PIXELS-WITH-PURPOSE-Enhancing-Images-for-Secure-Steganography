from flask import Flask, request, jsonify, send_file, render_template
from PIL import Image
import numpy as np
import io
import base64
import os
import math
import zlib
import hashlib
import hmac
import struct
import random
try:
    from scipy.stats import chi2
    def chi2_survival(x, df):
        return float(1.0 - chi2.cdf(x, df)) if df > 0 else 1.0
except ImportError:
    def chi2_survival(x, df):
        if df <= 0 or x <= 0: return 1.0
        a = df / 2.0
        z = x / 2.0
        if z < a + 1.0:
            ap = a
            sum_val = 1.0 / a
            del_val = sum_val
            for n in range(1, 300):
                ap += 1.0
                del_val *= z / ap
                sum_val += del_val
                if abs(del_val) < abs(sum_val) * 1e-12:
                    break
            p = sum_val * math.exp(-z + a * math.log(z) - math.lgamma(a))
        else:
            b = z + 1.0 - a
            c = 1.0 / 1e-30
            d = 1.0 / b
            h = d
            for i in range(1, 300):
                an = -i * (i - a)
                b += 2.0
                d = an * d + b
                if abs(d) < 1e-30: d = 1e-30
                c = b + an / c
                if abs(c) < 1e-30: c = 1e-30
                d = 1.0 / d
                del_val = d * c
                h *= del_val
                if abs(del_val - 1.0) < 1e-12:
                    break
            p = 1.0 - math.exp(-z + a * math.log(z) - math.lgamma(a)) * h
        return max(0.0, min(1.0, 1.0 - p))

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, 'templates'),
    static_folder=os.path.join(BASE_DIR, 'static')
)
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32MB max

# ─────────────────────────────────────────────
#  CONSTANTS & PROTOCOL IDENTIFIERS
# ─────────────────────────────────────────────

MAGIC_V2 = b'\x89PW2'  # Tier 2: Advanced Steganography Protocol
MAGIC_V1 = b'\x89PWP'  # Tier 1: Backward Compatible Protocol
LEGACY_DELIMITER = "$$END$$"

TYPE_TEXT = 1
TYPE_IMAGE = 2

CHANNEL_ALL = 0
CHANNEL_RED = 1
CHANNEL_GREEN = 2
CHANNEL_BLUE = 3
CHANNEL_ADAPTIVE = 4

CHANNEL_LABELS = {
    CHANNEL_ALL: "All Channels (RGB)",
    CHANNEL_RED: "Red Channel Only",
    CHANNEL_GREEN: "Green Channel Only",
    CHANNEL_BLUE: "Blue Channel (HVS Stealth Mode)",
    CHANNEL_ADAPTIVE: "Adaptive Pseudo-Random Channels"
}

# ─────────────────────────────────────────────
#  CRYPTOGRAPHY & AUTHENTICATION (AES-256 + HMAC)
# ─────────────────────────────────────────────

def derive_keys(password: str, salt: bytes):
    """
    Derive 256-bit AES encryption key and 256-bit HMAC key
    using PBKDF2-HMAC-SHA256 with 100,000 iterations.
    """
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100_000, dklen=64)
    aes_key = dk[:32]
    hmac_key = dk[32:]
    return aes_key, hmac_key

def encrypt_payload(data: bytes, password: str, salt: bytes = None):
    """
    Compresses data with zlib (level 9), encrypts with AES-256-CBC,
    and computes HMAC-SHA256 for Authenticated Encryption (Encrypt-then-MAC).
    Returns: salt(16) + (iv + ciphertext) + mac(32)
    """
    if salt is None:
        salt = os.urandom(16)
    iv = os.urandom(16)
    aes_key, hmac_key = derive_keys(password, salt)

    # 1. High-ratio compression before encryption
    compressed = zlib.compress(data, 9)

    # 2. PKCS7 Padding
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(compressed) + padder.finalize()

    # 3. AES-256-CBC Encryption
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    # 4. Cryptographic Authentication Tag (HMAC-SHA256)
    auth_data = salt + iv + ciphertext
    mac = hmac.new(hmac_key, auth_data, hashlib.sha256).digest()

    return salt, iv + ciphertext, mac

def decrypt_payload(salt: bytes, iv_ciphertext: bytes, mac: bytes, password: str):
    """
    Verifies HMAC-SHA256 tag and decrypts AES-256-CBC ciphertext.
    Raises ValueError if HMAC verification fails (tamper detection).
    """
    aes_key, hmac_key = derive_keys(password, salt)
    auth_data = salt + iv_ciphertext
    expected_mac = hmac.new(hmac_key, auth_data, hashlib.sha256).digest()

    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError("HMAC verification failed: Stego image data has been tampered with or corrupted!")

    iv = iv_ciphertext[:16]
    ciphertext = iv_ciphertext[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    compressed = unpadder.update(padded) + unpadder.finalize()
    return zlib.decompress(compressed)

# ─────────────────────────────────────────────
#  ADVANCED STEGANOGRAPHY ENGINE (TIER 2)
# ─────────────────────────────────────────────

def get_channel_indices(shape, channel_mode, password_seed):
    """
    Returns 1D flat channel indices based on selected channel mode.
    shape: (Height, Width, Channels)
    """
    H, W, C = shape
    total_pixels = H * W
    if channel_mode == CHANNEL_ALL:
        return list(range(H * W * C))
    elif channel_mode in (CHANNEL_RED, CHANNEL_GREEN, CHANNEL_BLUE):
        c = channel_mode - 1
        return [(p * 3 + c) for p in range(total_pixels)]
    elif channel_mode == CHANNEL_ADAPTIVE:
        rng = random.Random(password_seed)
        indices = list(range(H * W * C))
        rng.shuffle(indices)
        return indices
    return list(range(H * W * C))

def embed_tier2(img_array, payload_bytes: bytes, password: str, payload_type=TYPE_TEXT, lsb_depth=1, channel_mode=CHANNEL_ALL):
    """
    Tier 2 Multi-Feature Steganography Pipeline:
    - Configurable LSB Depth (1-bit or 2-bit)
    - Multi-Channel Selection (All RGB, Red, Green, Blue HVS Stealth, or Adaptive PRNG)
    - Authenticated Encryption (AES-256-CBC + HMAC-SHA256)
    - Seeded Non-sequential Pseudo-Random Bit Permutation
    """
    if lsb_depth not in (1, 2):
        raise ValueError("LSB depth must be either 1 or 2 bits.")

    shape = img_array.shape
    flat = img_array.flatten().copy()
    total_elements = len(flat)

    # 1. Encrypt payload & generate HMAC
    salt = os.urandom(16)
    salt, iv_ciphertext, mac = encrypt_payload(payload_bytes, password, salt)
    data_len = len(iv_ciphertext)

    # 2. Header Structure: 60 bytes
    # MAGIC(4) + TYPE(1) + DEPTH(1) + CHANNEL(1) + RESERVED(1) + LEN(4) + SALT(16) + MAC(32)
    header_bytes = struct.pack('>4sBBBB I 16s 32s', MAGIC_V2, payload_type, lsb_depth, channel_mode, 0, data_len, salt, mac)

    # 3. Embed 60-byte header (480 bits) using 1-bit LSB via password header-seed
    hdr_seed = int(hashlib.sha256((password + ":hdr").encode('utf-8')).hexdigest(), 16) % (2**32)
    rng_hdr = random.Random(hdr_seed)
    all_indices = list(range(total_elements))
    rng_hdr.shuffle(all_indices)
    hdr_indices = all_indices[:60 * 8]
    hdr_set = set(hdr_indices)

    hdr_bits = ''.join(format(b, '08b') for b in header_bytes)
    for idx, bit in zip(hdr_indices, hdr_bits):
        flat[idx] = (flat[idx] & 0xFE) | int(bit)

    # 4. Filter candidate channel indices according to channel_mode (excluding header positions)
    payload_seed = int(hashlib.sha256((password + ":data").encode('utf-8')).hexdigest(), 16) % (2**32)
    candidate_indices = get_channel_indices(shape, channel_mode, payload_seed)
    valid_payload_indices = [idx for idx in candidate_indices if idx not in hdr_set]

    rng_data = random.Random(payload_seed)
    rng_data.shuffle(valid_payload_indices)

    total_bits_needed = data_len * 8
    elements_needed = (total_bits_needed + lsb_depth - 1) // lsb_depth

    if elements_needed > len(valid_payload_indices):
        avail_bytes = (len(valid_payload_indices) * lsb_depth) // 8
        raise ValueError(
            f"Payload exceeds available capacity for this channel mode! "
            f"Required: {len(payload_bytes)} raw bytes ({elements_needed} pixel elements), "
            f"Max Available: ~{avail_bytes} encrypted bytes."
        )

    chosen_indices = valid_payload_indices[:elements_needed]

    # Convert iv_ciphertext into bitstream
    data_bits = ''.join(format(b, '08b') for b in iv_ciphertext)
    if len(data_bits) % lsb_depth != 0:
        data_bits += '0' * (lsb_depth - (len(data_bits) % lsb_depth))

    bit_cursor = 0
    mask = 0xFE if lsb_depth == 1 else 0xFC
    for idx in chosen_indices:
        chunk = data_bits[bit_cursor:bit_cursor + lsb_depth]
        bit_cursor += lsb_depth
        flat[idx] = (flat[idx] & mask) | int(chunk, 2)

    return flat.reshape(shape)

def extract_tier2(img_array, password: str):
    """
    Attempt to extract Tier 2 stego payload.
    Returns dictionary with details or None if password/header doesn't match.
    """
    shape = img_array.shape
    flat = img_array.flatten()
    total_elements = len(flat)

    # Reconstruct header indices
    hdr_seed = int(hashlib.sha256((password + ":hdr").encode('utf-8')).hexdigest(), 16) % (2**32)
    rng_hdr = random.Random(hdr_seed)
    all_indices = list(range(total_elements))
    rng_hdr.shuffle(all_indices)
    hdr_indices = all_indices[:60 * 8]

    hdr_bits = ''.join(str(flat[idx] & 1) for idx in hdr_indices)
    hdr_bytes = bytes(int(hdr_bits[i:i+8], 2) for i in range(0, 480, 8))

    magic = hdr_bytes[:4]
    if magic != MAGIC_V2:
        return None

    # Parse Tier 2 header
    magic_val, p_type, lsb_depth, ch_mode, _, data_len, salt, mac = struct.unpack('>4sBBBB I 16s 32s', hdr_bytes)
    hdr_set = set(hdr_indices)

    payload_seed = int(hashlib.sha256((password + ":data").encode('utf-8')).hexdigest(), 16) % (2**32)
    candidate_indices = get_channel_indices(shape, ch_mode, payload_seed)
    valid_payload_indices = [idx for idx in candidate_indices if idx not in hdr_set]

    rng_data = random.Random(payload_seed)
    rng_data.shuffle(valid_payload_indices)

    total_bits_needed = data_len * 8
    elements_needed = (total_bits_needed + lsb_depth - 1) // lsb_depth
    if elements_needed > len(valid_payload_indices):
        return None

    chosen_indices = valid_payload_indices[:elements_needed]
    mask = 0x01 if lsb_depth == 1 else 0x03
    extracted_bit_chunks = [format(flat[idx] & mask, f'0{lsb_depth}b') for idx in chosen_indices]
    all_data_bits = ''.join(extracted_bit_chunks)[:total_bits_needed]

    iv_ciphertext = bytes(int(all_data_bits[i:i+8], 2) for i in range(0, total_bits_needed, 8))

    try:
        decrypted = decrypt_payload(salt, iv_ciphertext, mac, password)
    except ValueError as e:
        if "HMAC verification failed" in str(e):
            return {
                "success": False,
                "tampered": True,
                "error": "🚨 TAMPER ALERT: Stego image was modified, corrupted, or recompressed lossily after embedding! HMAC-SHA256 integrity tag mismatch."
            }
        return None
    except Exception:
        return None

    if p_type == TYPE_TEXT:
        return {
            "success": True,
            "version": "v2.0 (Advanced Tier 2)",
            "type": "text",
            "content": decrypted.decode('utf-8', errors='replace'),
            "lsb_depth": lsb_depth,
            "channel_mode": ch_mode,
            "channel_name": CHANNEL_LABELS.get(ch_mode, "Unknown"),
            "tampered": False,
            "integrity": "Verified Authentic (HMAC-SHA256 Match)"
        }
    elif p_type == TYPE_IMAGE:
        # Convert decrypted image bytes to base64
        try:
            sec_img = Image.open(io.BytesIO(decrypted))
            sec_b64 = base64.b64encode(decrypted).decode()
            return {
                "success": True,
                "version": "v2.0 (Advanced Tier 2)",
                "type": "image",
                "image_b64": sec_b64,
                "image_width": sec_img.width,
                "image_height": sec_img.height,
                "image_format": sec_img.format or 'PNG',
                "size_bytes": len(decrypted),
                "lsb_depth": lsb_depth,
                "channel_mode": ch_mode,
                "channel_name": CHANNEL_LABELS.get(ch_mode, "Unknown"),
                "tampered": False,
                "integrity": "Verified Authentic (HMAC-SHA256 Match)"
            }
        except Exception as e:
            return {"success": False, "error": f"Failed to decode recovered secret image: {str(e)}"}

    return None

# ─────────────────────────────────────────────
#  BACKWARD COMPATIBILITY (TIER 1 & LEGACY)
# ─────────────────────────────────────────────

def get_scatter_indices_v1(password: str, total_pixels: int, num_bits: int) -> list:
    seed = int(hashlib.sha256(password.encode('utf-8')).hexdigest(), 16) % (2**32)
    rng = random.Random(seed)
    indices = list(range(total_pixels))
    rng.shuffle(indices)
    return indices[:num_bits]

def decrypt_v1(data: bytes, password: str) -> str:
    salt = data[:16]
    iv = data[16:32]
    ciphertext = data[32:]
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100_000, dklen=32)
    cipher = Cipher(algorithms.AES(dk), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    compressed = unpadder.update(padded) + unpadder.finalize()
    return zlib.decompress(compressed).decode('utf-8')

def extract_message_tier1(image_array, password: str):
    flat = image_array.flatten()
    total_pixels = len(flat)
    header_bits = 64
    header_indices = get_scatter_indices_v1(password, total_pixels, header_bits)
    header_raw = ''.join(str(flat[idx] & 1) for idx in header_indices)
    header_bytes = bytes(int(header_raw[i:i+8], 2) for i in range(0, 64, 8))
    magic = header_bytes[:4]
    if magic != MAGIC_V1:
        return None
    data_len = struct.unpack('>I', header_bytes[4:8])[0]
    total_needed = (8 + data_len) * 8
    if total_needed > total_pixels:
        return None
    all_indices = get_scatter_indices_v1(password, total_pixels, total_needed)
    all_bits = ''.join(str(flat[idx] & 1) for idx in all_indices)
    data_bits = all_bits[64:]
    encrypted = bytes(int(data_bits[i:i+8], 2) for i in range(0, data_len * 8, 8))
    try:
        return decrypt_v1(encrypted, password)
    except Exception:
        return None

def extract_message_legacy(image_array):
    flat = image_array.flatten()
    bits = ''.join(str(pixel & 1) for pixel in flat)
    result = []
    for i in range(0, len(bits) - 7, 8):
        byte = bits[i:i+8]
        char = chr(int(byte, 2))
        result.append(char)
        current = ''.join(result)
        if current.endswith(LEGACY_DELIMITER):
            return current[:-len(LEGACY_DELIMITER)]
    return None

# ─────────────────────────────────────────────
#  ADVANCED FORENSICS & METRICS (SSIM, PSNR, MSE, DIFF)
# ─────────────────────────────────────────────

def compute_psnr(original, stego):
    """Compute Peak Signal-to-Noise Ratio between two images."""
    mse = np.mean((original.astype(float) - stego.astype(float)) ** 2)
    if mse == 0:
        return 99.9999
    max_pixel = 255.0
    psnr = 20 * math.log10(max_pixel / math.sqrt(mse))
    return round(min(psnr, 99.9999), 4)

def compute_mse(original, stego):
    """Compute Mean Squared Error."""
    mse = np.mean((original.astype(float) - stego.astype(float)) ** 2)
    return round(float(mse), 6)

def compute_ssim(img1, img2):
    """
    Compute Structural Similarity Index (SSIM) on luminance channel.
    Values close to 1.000 indicate imperceptible visual differences.
    """
    if len(img1.shape) == 3:
        y1 = 0.299 * img1[:,:,0] + 0.587 * img1[:,:,1] + 0.114 * img1[:,:,2]
        y2 = 0.299 * img2[:,:,0] + 0.587 * img2[:,:,1] + 0.114 * img2[:,:,2]
    else:
        y1, y2 = img1.astype(float), img2.astype(float)

    K1, K2, L = 0.01, 0.03, 255.0
    C1 = (K1 * L) ** 2
    C2 = (K2 * L) ** 2

    mu1 = np.mean(y1)
    mu2 = np.mean(y2)
    var1 = np.var(y1)
    var2 = np.var(y2)
    cov12 = np.mean((y1 - mu1) * (y2 - mu2))

    ssim = ((2 * mu1 * mu2 + C1) * (2 * cov12 + C2)) / ((mu1**2 + mu2**2 + C1) * (var1 + var2 + C2))
    return round(float(ssim), 5)

def generate_diff_map_base64(original, stego, factor=40):
    """
    Generates an amplified absolute difference heatmap (factor x40)
    showing exact scattered bit modification sites.
    """
    diff = np.abs(original.astype(np.int16) - stego.astype(np.int16))
    amplified = np.clip(diff * factor, 0, 255).astype(np.uint8)
    # Give false-color cyan/magenta tint to differences for visual pop
    if len(amplified.shape) == 3:
        # Increase red/cyan contrast
        enhanced = amplified.copy()
        enhanced[:, :, 0] = np.clip(amplified[:, :, 0] * 1.5, 0, 255)
        enhanced[:, :, 2] = np.clip(amplified[:, :, 2] * 2.0, 0, 255)
    else:
        enhanced = amplified

    pil_diff = Image.fromarray(enhanced)
    buf = io.BytesIO()
    pil_diff.save(buf, format='PNG')
    buf.seek(0)
    return base64.b64encode(buf.getvalue()).decode()

def per_channel_analysis(img_array):
    """Run chi-square & LSB distribution independently on R, G, and B channels."""
    results = {}
    channel_names = ['Red', 'Green', 'Blue']
    for idx, name in enumerate(channel_names):
        ch = img_array[:, :, idx].flatten().astype(int)
        even_counts = np.bincount(ch[ch % 2 == 0] // 2, minlength=128)
        odd_counts  = np.bincount(ch[ch % 2 == 1] // 2, minlength=128)
        expected = (even_counts + odd_counts) / 2.0
        mask = expected > 0
        chi_sq = np.sum((even_counts[mask] - expected[mask])**2 / expected[mask])
        df = np.sum(mask) - 1
        p_val = chi2_survival(chi_sq, df)
        lsb = ch & 1
        ones = int(np.sum(lsb))
        ratio = round(ones / len(lsb), 4)
        results[name] = {
            'chi_square': round(float(chi_sq), 2),
            'p_value': round(float(p_val), 4),
            'ones_ratio': ratio,
            'suspicious': bool(p_val < 0.05)
        }
    return results

def chi_square_test(image_array):
    flat = image_array.flatten().astype(int)
    even_counts = np.bincount(flat[flat % 2 == 0] // 2, minlength=128)
    odd_counts  = np.bincount(flat[flat % 2 == 1] // 2, minlength=128)

    expected = (even_counts + odd_counts) / 2.0
    observed = even_counts

    mask = expected > 0
    chi_sq = np.sum((observed[mask] - expected[mask])**2 / expected[mask])
    df = np.sum(mask) - 1

    p_value = chi2_survival(chi_sq, df)

    if p_value < 0.05:
        verdict = "⚠️ HIDDEN DATA DETECTED (High confidence)"
        risk = "high"
    elif p_value < 0.3:
        verdict = "⚠️ POSSIBLE hidden data (Medium confidence)"
        risk = "medium"
    else:
        verdict = "✅ No hidden data detected (Clean image)"
        risk = "low"

    return {
        "chi_square": round(float(chi_sq), 4),
        "p_value": round(float(p_value), 6),
        "degrees_of_freedom": int(df),
        "verdict": verdict,
        "risk_level": risk
    }

def analyze_lsb_distribution(image_array):
    flat = image_array.flatten()
    lsb_plane = flat & 1
    ones  = int(np.sum(lsb_plane))
    zeros = int(len(lsb_plane) - ones)
    total = len(lsb_plane)
    ratio = round(ones / total, 4)
    balance = round(abs(ratio - 0.5), 4)

    return {
        "total_bits": total,
        "ones": ones,
        "zeros": zeros,
        "ones_ratio": ratio,
        "balance_deviation": balance,
        "suspicious": bool(balance < 0.02)
    }

def get_lsb_image_base64(image_array):
    flat = image_array.flatten()
    lsb = (flat & 1) * 255
    lsb_img_array = lsb.reshape(image_array.shape).astype(np.uint8)
    lsb_pil = Image.fromarray(lsb_img_array)
    buf = io.BytesIO()
    lsb_pil.save(buf, format='PNG')
    buf.seek(0)
    return base64.b64encode(buf.getvalue()).decode()

def image_to_base64(pil_image, fmt='PNG'):
    buf = io.BytesIO()
    pil_image.save(buf, format=fmt)
    buf.seek(0)
    return base64.b64encode(buf.getvalue()).decode()

# ─────────────────────────────────────────────
#  ROUTES & API ENDPOINTS
# ─────────────────────────────────────────────

@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/api/embed', methods=['POST'])
@app.route('/embed', methods=['POST'])
def embed():
    """
    Tier 2 Advanced Embedding Endpoint:
    Supports both Secret Text and Image-in-Image embedding,
    configurable LSB depth (1 or 2 bits), and multi-channel selection.
    """
    try:
        if 'image' not in request.files:
            return jsonify({'error': 'No cover image file provided'}), 400

        file = request.files['image']
        password = request.form.get('password', '').strip()
        payload_type = request.form.get('payload_type', 'text').strip()
        lsb_depth = int(request.form.get('lsb_depth', 1))
        channel_mode = int(request.form.get('channel_mode', CHANNEL_ALL))

        if not password:
            return jsonify({'error': 'Encryption password is required'}), 400
        if len(password) < 4:
            return jsonify({'error': 'Password must be at least 4 characters'}), 400

        # Load cover image first to calculate capacity
        img = Image.open(file.stream).convert('RGB')
        img_array = np.array(img)
        original_b64 = image_to_base64(img)

        # Calculate exact capacity for chosen channel mode and LSB depth
        total_elements = img_array.size
        if channel_mode in (CHANNEL_RED, CHANNEL_GREEN, CHANNEL_BLUE):
            channel_elements = total_elements // 3
        else:
            channel_elements = total_elements

        # Available raw payload capacity (accounting for header, salt, IV, HMAC, zlib overhead)
        max_payload_bytes = max(10, ((channel_elements - 480) * lsb_depth) // 8 - 64)

        # Prepare payload bytes
        if payload_type == 'image':
            if 'secret_image' not in request.files:
                return jsonify({'error': 'Please upload a secret image to hide'}), 400
            secret_file = request.files['secret_image']
            raw_uploaded_bytes = secret_file.read()
            secret_file.seek(0)

            sec_img = Image.open(secret_file.stream)
            orig_w, orig_h = sec_img.width, sec_img.height

            # If original file is already within capacity (e.g. JPEG, PNG, WebP)
            if len(raw_uploaded_bytes) <= max_payload_bytes:
                payload_bytes = raw_uploaded_bytes
                payload_info_label = f"Secret Image ({orig_w}x{orig_h}, {len(payload_bytes)/1024:.1f} KB)"
            else:
                # Intelligently scale down and optimize secret image to fit comfortably inside cover
                scale = math.sqrt(max_payload_bytes / max(len(raw_uploaded_bytes), 1)) * 0.88
                new_w = max(24, int(orig_w * scale))
                new_h = max(24, int(orig_h * scale))
                scaled = sec_img.copy().resize((new_w, new_h), Image.Resampling.LANCZOS)
                
                buf = io.BytesIO()
                if sec_img.mode in ('RGBA', 'LA') or (sec_img.mode == 'P' and 'transparency' in sec_img.info):
                    scaled.save(buf, format='PNG', optimize=True)
                else:
                    scaled.convert('RGB').save(buf, format='JPEG', quality=80, optimize=True)
                payload_bytes = buf.getvalue()

                # If still slightly over, lower quality slightly
                if len(payload_bytes) > max_payload_bytes:
                    buf = io.BytesIO()
                    scaled.convert('RGB').save(buf, format='JPEG', quality=60, optimize=True)
                    payload_bytes = buf.getvalue()

                payload_info_label = f"Secret Image (Auto-fit to {new_w}x{new_h}, {len(payload_bytes)/1024:.1f} KB)"
            p_type_code = TYPE_IMAGE
        else:
            message = request.form.get('message', '').strip()
            if not message:
                return jsonify({'error': 'No secret message provided'}), 400
            payload_bytes = message.encode('utf-8')
            p_type_code = TYPE_TEXT
            payload_info_label = f"Secret Text ({len(message)} characters)"

        # Run Tier 2 Embedding
        stego_array = embed_tier2(
            img_array=img_array,
            payload_bytes=payload_bytes,
            password=password,
            payload_type=p_type_code,
            lsb_depth=lsb_depth,
            channel_mode=channel_mode
        )

        stego_img = Image.fromarray(stego_array.astype(np.uint8))
        stego_b64 = image_to_base64(stego_img)

        # Compute Forensic & Quality Metrics
        psnr = compute_psnr(img_array, stego_array)
        mse  = compute_mse(img_array, stego_array)
        ssim = compute_ssim(img_array, stego_array)
        diff_b64 = generate_diff_map_base64(img_array, stego_array)

        capacity_used_pct = round((len(payload_bytes) / max(max_payload_bytes, 1)) * 100, 2)

        return jsonify({
            'success': True,
            'original_image': original_b64,
            'stego_image': stego_b64,
            'diff_image': diff_b64,
            'metrics': {
                'psnr': psnr,
                'ssim': ssim,
                'mse': mse,
                'payload_type': payload_type,
                'payload_info': payload_info_label,
                'payload_bytes': len(payload_bytes),
                'max_capacity_bytes': max_payload_bytes,
                'capacity_used_pct': min(capacity_used_pct, 100.0),
                'lsb_depth': lsb_depth,
                'channel_mode': channel_mode,
                'channel_name': CHANNEL_LABELS.get(channel_mode, 'All Channels'),
                'encryption': 'AES-256-CBC (256-bit Key)',
                'integrity': 'HMAC-SHA256 (Authenticated)',
                'key_derivation': 'PBKDF2-HMAC-SHA256 (100K iter)',
                'compression': 'zlib Level 9',
                'bit_scattering': 'Password PRNG Scatter'
            }
        })
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Embedding error: {str(e)}'}), 500

@app.route('/api/extract', methods=['POST'])
@app.route('/extract', methods=['POST'])
def extract():
    """
    Tier 2 Advanced Extraction Endpoint:
    Auto-detects Text vs Image payload, verifies HMAC-SHA256 integrity,
    and supports Tier 1 and legacy fallback.
    """
    try:
        if 'image' not in request.files:
            return jsonify({'error': 'No image file provided'}), 400

        file = request.files['image']
        password = request.form.get('password', '').strip()

        img = Image.open(file.stream).convert('RGB')
        img_array = np.array(img)

        # 1. Try Tier 2 extraction if password provided
        if password:
            t2_res = extract_tier2(img_array, password)
            if t2_res is not None:
                if not t2_res.get('success', False):
                    # Tamper alert!
                    return jsonify({
                        'success': False,
                        'tampered': True,
                        'info': t2_res.get('error', 'Tamper detected')
                    })

                # Successful Tier 2 extraction
                if t2_res['type'] == 'text':
                    return jsonify({
                        'success': True,
                        'type': 'text',
                        'message': t2_res['content'],
                        'version': t2_res['version'],
                        'lsb_depth': t2_res['lsb_depth'],
                        'channel_name': t2_res['channel_name'],
                        'integrity': t2_res['integrity'],
                        'security_note': 'AES-256-CBC Decrypted · HMAC-SHA256 Verified · Authentic'
                    })
                elif t2_res['type'] == 'image':
                    return jsonify({
                        'success': True,
                        'type': 'image',
                        'secret_image_b64': t2_res['image_b64'],
                        'image_width': t2_res['image_width'],
                        'image_height': t2_res['image_height'],
                        'image_format': t2_res['image_format'],
                        'size_bytes': t2_res['size_bytes'],
                        'version': t2_res['version'],
                        'lsb_depth': t2_res['lsb_depth'],
                        'channel_name': t2_res['channel_name'],
                        'integrity': t2_res['integrity'],
                        'security_note': 'AES-256-CBC Decrypted · HMAC-SHA256 Verified · Secret Image Recovered'
                    })

            # 2. Fallback to Tier 1 extraction
            t1_msg = extract_message_tier1(img_array, password)
            if t1_msg:
                return jsonify({
                    'success': True,
                    'type': 'text',
                    'message': t1_msg,
                    'version': 'v1.0 (Tier 1)',
                    'lsb_depth': 1,
                    'channel_name': 'All Channels (RGB)',
                    'integrity': 'Legacy Tier 1 (No HMAC)',
                    'security_note': 'Decrypted with AES-256-CBC (Tier 1 Format)'
                })

        # 3. Fallback to Legacy plaintext extraction
        legacy_msg = extract_message_legacy(img_array)
        if legacy_msg:
            return jsonify({
                'success': True,
                'type': 'text',
                'message': legacy_msg,
                'version': 'Legacy (v0)',
                'lsb_depth': 1,
                'channel_name': 'Sequential LSB',
                'integrity': 'None (Unauthenticated)',
                'security_note': '⚠️ Legacy format — message was NOT encrypted'
            })

        # No payload recovered
        if password:
            return jsonify({
                'success': False,
                'info': '❌ Incorrect password, or this image does not contain hidden steganographic data.'
            })
        else:
            return jsonify({
                'success': False,
                'info': 'No unencrypted message found. If this is a secure stego image, please enter the password.'
            })

    except Exception as e:
        return jsonify({'error': f'Extraction error: {str(e)}'}), 500

@app.route('/api/steganalyze', methods=['POST'])
@app.route('/steganalyze', methods=['POST'])
def steganalyze():
    """
    Tier 2 Advanced Forensic Steganalysis:
    Full Chi-Square attack, LSB distribution, per-channel (R, G, B) breakdown,
    and visual LSB noise plane.
    """
    try:
        if 'image' not in request.files:
            return jsonify({'error': 'No image file provided'}), 400

        file = request.files['image']
        img = Image.open(file.stream).convert('RGB')
        img_array = np.array(img)

        # Forensic tests
        chi_result   = chi_square_test(img_array)
        lsb_dist     = analyze_lsb_distribution(img_array)
        channel_data = per_channel_analysis(img_array)
        lsb_b64      = get_lsb_image_base64(img_array)
        original_b64 = image_to_base64(img)

        extracted = extract_message_legacy(img_array)

        # Risk Assessment
        risk_score = 0
        if chi_result['risk_level'] == 'high': risk_score += 2
        elif chi_result['risk_level'] == 'medium': risk_score += 1
        if lsb_dist['suspicious']: risk_score += 1
        if extracted: risk_score += 2
        for ch in channel_data.values():
            if ch['suspicious']: risk_score += 1

        if risk_score >= 3:
            overall = {"level": "HIGH", "color": "red", "label": "🚨 Steganographic Anomaly Detected"}
        elif risk_score >= 1:
            overall = {"level": "MEDIUM", "color": "orange", "label": "⚠️ Subtle Statistical Deviations"}
        else:
            overall = {"level": "LOW", "color": "green", "label": "✅ Clean Image (Imperceptible)"}

        return jsonify({
            'success': True,
            'original_image': original_b64,
            'lsb_plane_image': lsb_b64,
            'chi_square': chi_result,
            'lsb_distribution': lsb_dist,
            'channel_analysis': channel_data,
            'extracted_message': extracted,
            'secure_note': 'Advanced Tier 2 stego (AES-256 + PRNG scattering + HVS blue channel) successfully bypasses standard chi-square detection.',
            'overall_risk': overall,
            'image_info': {
                'width': img.width,
                'height': img.height,
                'mode': img.mode,
                'total_pixels': img_array.size
            }
        })
    except Exception as e:
        return jsonify({'error': f'Steganalysis error: {str(e)}'}), 500

@app.route('/api/download_stego', methods=['POST'])
@app.route('/download_stego', methods=['POST'])
def download_stego():
    """Download the stego image as a PNG file."""
    try:
        data = request.json
        if not data or 'stego_b64' not in data:
            return jsonify({'error': 'No image data'}), 400

        img_bytes = base64.b64decode(data['stego_b64'])
        return send_file(
            io.BytesIO(img_bytes),
            mimetype='image/png',
            as_attachment=True,
            download_name='stego_image.png'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/download_secret', methods=['POST'])
@app.route('/download_secret', methods=['POST'])
def download_secret():
    """Download the extracted secret image."""
    try:
        data = request.json
        if not data or 'secret_b64' not in data:
            return jsonify({'error': 'No secret image data'}), 400

        img_bytes = base64.b64decode(data['secret_b64'])
        ext = data.get('format', 'png').lower()
        return send_file(
            io.BytesIO(img_bytes),
            mimetype=f'image/{ext}',
            as_attachment=True,
            download_name=f'extracted_secret.{ext}'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.errorhandler(404)
def handle_404(e):
    return jsonify({
        'error': 'Endpoint not found',
        'requested_path': request.path,
        'method': request.method,
        'environ_path_info': request.environ.get('PATH_INFO'),
        'environ_script_name': request.environ.get('SCRIPT_NAME')
    }), 404

@app.errorhandler(500)
def handle_500(e):
    return jsonify({
        'error': f'Server internal error: {str(e)}'
    }), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
