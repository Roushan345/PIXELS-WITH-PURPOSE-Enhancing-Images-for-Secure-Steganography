from flask import Flask, request, jsonify, send_file, render_template
from PIL import Image
import numpy as np
import io
import base64
import os
import math
from scipy.stats import chi2

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

# ─────────────────────────────────────────────
#  LSB STEGANOGRAPHY CORE
# ─────────────────────────────────────────────

DELIMITER = "$$END$$"

def text_to_bits(text):
    """Convert text string to binary string."""
    bits = ''.join(format(ord(c), '08b') for c in text)
    return bits

def bits_to_text(bits):
    """Convert binary string back to text."""
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) == 8:
            chars.append(chr(int(byte, 2)))
    return ''.join(chars)

def embed_message(image_array, message):
    """Embed a text message into image using LSB technique."""
    full_message = message + DELIMITER
    bits = text_to_bits(full_message)
    total_bits = len(bits)

    flat = image_array.flatten().copy()
    if total_bits > len(flat):
        raise ValueError(f"Message too long! Max ~{len(flat)//8} characters for this image.")

    for i, bit in enumerate(bits):
        flat[i] = (flat[i] & 0xFE) | int(bit)

    return flat.reshape(image_array.shape)

def extract_message(image_array):
    """Extract hidden message from image using LSB technique."""
    flat = image_array.flatten()
    bits = ''.join(str(pixel & 1) for pixel in flat)

    # Decode in chunks and look for delimiter
    result = []
    for i in range(0, len(bits) - 7, 8):
        byte = bits[i:i+8]
        char = chr(int(byte, 2))
        result.append(char)
        current = ''.join(result)
        if current.endswith(DELIMITER):
            return current[:-len(DELIMITER)]

    return None

# ─────────────────────────────────────────────
#  STEGANALYSIS FUNCTIONS
# ─────────────────────────────────────────────

def compute_psnr(original, stego):
    """Compute Peak Signal-to-Noise Ratio between two images."""
    mse = np.mean((original.astype(float) - stego.astype(float)) ** 2)
    if mse == 0:
        return 99.9999   # Perfect quality — cap at 99.9999 (JSON-safe, no infinity)
    max_pixel = 255.0
    psnr = 20 * math.log10(max_pixel / math.sqrt(mse))
    return round(min(psnr, 99.9999), 4)  # Cap to avoid JSON infinity issues

def compute_mse(original, stego):
    """Compute Mean Squared Error."""
    mse = np.mean((original.astype(float) - stego.astype(float)) ** 2)
    return round(float(mse), 6)

def chi_square_test(image_array):
    """
    Chi-Square steganalysis on the image.
    Tests if LSB plane has uniform distribution (sign of embedding).
    Returns p-value and verdict.
    """
    flat = image_array.flatten().astype(int)
    # Pair up even-odd values (PoVs - Pairs of Values)
    even_counts = np.bincount(flat[flat % 2 == 0] // 2, minlength=128)
    odd_counts  = np.bincount(flat[flat % 2 == 1] // 2, minlength=128)

    expected = (even_counts + odd_counts) / 2.0
    observed = even_counts

    mask = expected > 0
    chi_sq = np.sum((observed[mask] - expected[mask])**2 / expected[mask])
    df = np.sum(mask) - 1

    p_value = 1 - chi2.cdf(chi_sq, df) if df > 0 else 1.0

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
    """Analyze LSB plane distribution for anomalies."""
    flat = image_array.flatten()
    lsb_plane = flat & 1
    ones  = int(np.sum(lsb_plane))
    zeros = int(len(lsb_plane) - ones)
    total = len(lsb_plane)
    ratio = round(ones / total, 4)

    # Natural images tend to have ~50% ones in LSB — embedding also gives ~50%
    # but with a very flat histogram pattern
    balance = round(abs(ratio - 0.5), 4)

    return {
        "total_bits": total,
        "ones": ones,
        "zeros": zeros,
        "ones_ratio": ratio,
        "balance_deviation": balance,
        "suspicious": balance < 0.02  # Very flat = suspicious
    }

def get_lsb_image_base64(image_array):
    """Generate a visualizable LSB plane image (amplified for visibility)."""
    flat = image_array.flatten()
    lsb = (flat & 1) * 255
    lsb_img_array = lsb.reshape(image_array.shape).astype(np.uint8)
    lsb_pil = Image.fromarray(lsb_img_array)
    buf = io.BytesIO()
    lsb_pil.save(buf, format='PNG')
    buf.seek(0)
    return base64.b64encode(buf.getvalue()).decode()

def image_to_base64(pil_image, fmt='PNG'):
    """Convert PIL image to base64 string."""
    buf = io.BytesIO()
    pil_image.save(buf, format=fmt)
    buf.seek(0)
    return base64.b64encode(buf.getvalue()).decode()

# ─────────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/embed', methods=['POST'])
def embed():
    """Embed secret message into uploaded image."""
    try:
        if 'image' not in request.files:
            return jsonify({'error': 'No image file provided'}), 400

        file = request.files['image']
        message = request.form.get('message', '').strip()

        if not message:
            return jsonify({'error': 'No message provided'}), 400

        # Load image
        img = Image.open(file.stream).convert('RGB')
        img_array = np.array(img)
        original_b64 = image_to_base64(img)

        # Embed message
        stego_array = embed_message(img_array, message)
        stego_img = Image.fromarray(stego_array.astype(np.uint8))
        stego_b64 = image_to_base64(stego_img)

        # Compute metrics
        psnr = compute_psnr(img_array, stego_array)
        mse  = compute_mse(img_array, stego_array)

        # Max capacity info
        total_pixels = img_array.size
        max_chars = total_pixels // 8

        return jsonify({
            'success': True,
            'original_image': original_b64,
            'stego_image': stego_b64,
            'metrics': {
                'psnr': psnr,
                'mse': mse,
                'message_length': len(message),
                'bits_used': (len(message) + len(DELIMITER)) * 8,
                'max_capacity_chars': max_chars,
                'capacity_used_pct': round((len(message) / max_chars) * 100, 2)
            }
        })
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Processing error: {str(e)}'}), 500

@app.route('/api/extract', methods=['POST'])
def extract():
    """Extract hidden message from a stego image."""
    try:
        if 'image' not in request.files:
            return jsonify({'error': 'No image file provided'}), 400

        file = request.files['image']
        img = Image.open(file.stream).convert('RGB')
        img_array = np.array(img)

        message = extract_message(img_array)

        if message is None:
            return jsonify({
                'success': False,
                'message': None,
                'info': 'No hidden message found or message is corrupted.'
            })

        return jsonify({
            'success': True,
            'message': message,
            'message_length': len(message)
        })
    except Exception as e:
        return jsonify({'error': f'Extraction error: {str(e)}'}), 500

@app.route('/api/steganalyze', methods=['POST'])
def steganalyze():
    """Run full steganalysis on an uploaded image."""
    try:
        if 'image' not in request.files:
            return jsonify({'error': 'No image file provided'}), 400

        file = request.files['image']
        img = Image.open(file.stream).convert('RGB')
        img_array = np.array(img)

        # Run analyses
        chi_result   = chi_square_test(img_array)
        lsb_dist     = analyze_lsb_distribution(img_array)
        lsb_b64      = get_lsb_image_base64(img_array)
        original_b64 = image_to_base64(img)

        # Try to extract any message
        extracted = extract_message(img_array)

        # Overall risk assessment
        risk_score = 0
        if chi_result['risk_level'] == 'high': risk_score += 2
        elif chi_result['risk_level'] == 'medium': risk_score += 1
        if lsb_dist['suspicious']: risk_score += 1
        if extracted: risk_score += 2

        if risk_score >= 3:
            overall = {"level": "HIGH", "color": "red", "label": "🚨 Steganographic Content Likely"}
        elif risk_score >= 1:
            overall = {"level": "MEDIUM", "color": "orange", "label": "⚠️ Suspicious — Further Analysis Needed"}
        else:
            overall = {"level": "LOW", "color": "green", "label": "✅ Image Appears Clean"}

        return jsonify({
            'success': True,
            'original_image': original_b64,
            'lsb_plane_image': lsb_b64,
            'chi_square': chi_result,
            'lsb_distribution': lsb_dist,
            'extracted_message': extracted,
            'overall_risk': overall,
            'image_info': {
                'width': img.width,
                'height': img.height,
                'mode': img.mode,
                'total_pixels': img_array.size
            }
        })
    except Exception as e:
        return jsonify({'error': f'Analysis error: {str(e)}'}), 500

@app.route('/api/download_stego', methods=['POST'])
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

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
