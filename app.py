"""
Crypto-Web: Simulasi Algoritma Kriptografi Simetris
DES, S-DES, AES-128, S-AES - Flask backend.
Seluruh perhitungan algoritma dilakukan manual (lihat /algorithms), tanpa
menggunakan library `cryptography`/`pycryptodome` untuk proses inti.
"""
import re
from flask import Flask, render_template, request, jsonify

from algorithms import des, sdes, aes, saes

app = Flask(__name__)

HEX_RE = re.compile(r'^[0-9A-Fa-f]+$')
BIN_RE = re.compile(r'^[01]+$')


def to_binary(value, fmt, expected_bits):
    """Konversi input sesuai format eksplisit yang dipilih user ('binary'/'hex').
    Mengembalikan (bin_string, error, was_hex)."""
    value = (value or '').strip().replace(' ', '')
    if not value:
        return None, 'Input tidak boleh kosong.', False

    if fmt == 'hex':
        expected_hex_len = expected_bits // 4
        if not HEX_RE.match(value):
            return None, 'Format Hex tidak valid (hanya boleh 0-9, A-F).', True
        if len(value) != expected_hex_len:
            return None, f'Hex harus tepat {expected_hex_len} digit ({expected_bits} bit).', True
        b = bin(int(value, 16))[2:].zfill(expected_bits)
        return b, None, True

    # default: binary
    if not BIN_RE.match(value):
        return None, 'Format Biner tidak valid (hanya boleh 0 dan 1).', False
    if len(value) != expected_bits:
        return None, f'Biner harus tepat {expected_bits} bit (input Anda {len(value)} bit).', False
    return value, None, False


def bin_to_hex(b):
    return hex(int(b, 2))[2:].upper().zfill(len(b) // 4)


def build_input_info(label, original, fmt, bin_value):
    """Struktur info input untuk ditampilkan sebagai langkah 'Input' & 'Konversi' di solusi."""
    hex_value = bin_to_hex(bin_value) if len(bin_value) % 4 == 0 else None
    return {
        'label': label,
        'original': original,
        'format': fmt,
        'binary': bin_value,
        'hex': hex_value,
        'converted': fmt == 'hex'
    }


# --------------------------------------------------------------------------
# Page routes
# --------------------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/des')
def des_page():
    return render_template('des.html')


@app.route('/sdes')
def sdes_page():
    return render_template('sdes.html')


@app.route('/aes')
def aes_page():
    return render_template('aes.html')


@app.route('/saes')
def saes_page():
    return render_template('saes.html')


# --------------------------------------------------------------------------
# API: DES  (64-bit block, 64-bit key) - format Binary/Hex dipilih user
# --------------------------------------------------------------------------
@app.route('/api/des', methods=['POST'])
def api_des():
    data = request.get_json(force=True)
    mode = data.get('mode')
    text = data.get('text', '')
    key = data.get('key', '')
    text_fmt = data.get('text_format', 'binary')
    key_fmt = data.get('key_format', 'binary')

    key_bin, err, _ = to_binary(key, key_fmt, 64)
    if err:
        return jsonify({'error': f'Key: {err}'}), 400
    text_bin, err, _ = to_binary(text, text_fmt, 64)
    if err:
        field = 'Plaintext' if mode == 'encrypt' else 'Ciphertext'
        return jsonify({'error': f'{field}: {err}'}), 400

    key_hex = bin_to_hex(key_bin)
    text_hex = bin_to_hex(text_bin)

    if mode == 'encrypt':
        out_hex, out_bin, process = des.encrypt(text_hex, key_hex)
    elif mode == 'decrypt':
        out_hex, out_bin, process = des.decrypt(text_hex, key_hex)
    else:
        return jsonify({'error': 'Mode tidak valid.'}), 400

    text_label = 'Plaintext' if mode == 'encrypt' else 'Ciphertext'
    input_info = {
        'text': build_input_info(text_label, text, text_fmt, text_bin),
        'key': build_input_info('Key', key, key_fmt, key_bin),
    }
    return jsonify({'result_hex': out_hex, 'result_bin': out_bin, 'process': process, 'input_info': input_info})


# --------------------------------------------------------------------------
# API: S-DES (8-bit block, 10-bit key) - selalu Biner
# --------------------------------------------------------------------------
@app.route('/api/sdes', methods=['POST'])
def api_sdes():
    data = request.get_json(force=True)
    mode = data.get('mode')
    text = data.get('text', '')
    key = data.get('key', '')

    key_bin, err, _ = to_binary(key, 'binary', 10)
    if err:
        return jsonify({'error': f'Key: {err}'}), 400
    text_bin, err, _ = to_binary(text, 'binary', 8)
    if err:
        field = 'Plaintext' if mode == 'encrypt' else 'Ciphertext'
        return jsonify({'error': f'{field}: {err}'}), 400

    if mode == 'encrypt':
        out_hex, out_bin, process = sdes.encrypt(text_bin, key_bin)
    elif mode == 'decrypt':
        out_hex, out_bin, process = sdes.decrypt(text_bin, key_bin)
    else:
        return jsonify({'error': 'Mode tidak valid.'}), 400

    text_label = 'Plaintext' if mode == 'encrypt' else 'Ciphertext'
    input_info = {
        'text': build_input_info(text_label, text, 'binary', text_bin),
        'key': build_input_info('Key', key, 'binary', key_bin),
    }
    return jsonify({'result_hex': out_hex, 'result_bin': out_bin, 'process': process, 'input_info': input_info})


# --------------------------------------------------------------------------
# API: AES-128 (128-bit block, 128-bit key) - selalu Hex (32 digit)
# --------------------------------------------------------------------------
@app.route('/api/aes', methods=['POST'])
def api_aes():
    data = request.get_json(force=True)
    mode = data.get('mode')
    text = data.get('text', '')
    key = data.get('key', '')

    key_bin, err, _ = to_binary(key, 'hex', 128)
    if err:
        return jsonify({'error': f'Key: {err}'}), 400
    text_bin, err, _ = to_binary(text, 'hex', 128)
    if err:
        field = 'Plaintext' if mode == 'encrypt' else 'Ciphertext'
        return jsonify({'error': f'{field}: {err}'}), 400

    key_hex = bin_to_hex(key_bin)
    text_hex = bin_to_hex(text_bin)

    if mode == 'encrypt':
        out_hex, process = aes.encrypt(text_hex, key_hex)
    elif mode == 'decrypt':
        out_hex, process = aes.decrypt(text_hex, key_hex)
    else:
        return jsonify({'error': 'Mode tidak valid.'}), 400

    out_bin = bin(int(out_hex, 16))[2:].zfill(128)
    text_label = 'Plaintext' if mode == 'encrypt' else 'Ciphertext'
    input_info = {
        'text': build_input_info(text_label, text, 'hex', text_bin),
        'key': build_input_info('Key', key, 'hex', key_bin),
    }
    return jsonify({'result_hex': out_hex, 'result_bin': out_bin, 'process': process, 'input_info': input_info})


# --------------------------------------------------------------------------
# API: S-AES (16-bit block, 16-bit key) - format Binary/Hex dipilih user
# --------------------------------------------------------------------------
@app.route('/api/saes', methods=['POST'])
def api_saes():
    data = request.get_json(force=True)
    mode = data.get('mode')
    text = data.get('text', '')
    key = data.get('key', '')
    text_fmt = data.get('text_format', 'binary')
    key_fmt = data.get('key_format', 'binary')

    key_bin, err, _ = to_binary(key, key_fmt, 16)
    if err:
        return jsonify({'error': f'Key: {err}'}), 400
    text_bin, err, _ = to_binary(text, text_fmt, 16)
    if err:
        field = 'Plaintext' if mode == 'encrypt' else 'Ciphertext'
        return jsonify({'error': f'{field}: {err}'}), 400

    if mode == 'encrypt':
        out_hex, out_bin, process = saes.encrypt(text_bin, key_bin)
    elif mode == 'decrypt':
        out_hex, out_bin, process = saes.decrypt(text_bin, key_bin)
    else:
        return jsonify({'error': 'Mode tidak valid.'}), 400

    text_label = 'Plaintext' if mode == 'encrypt' else 'Ciphertext'
    input_info = {
        'text': build_input_info(text_label, text, text_fmt, text_bin),
        'key': build_input_info('Key', key, key_fmt, key_bin),
    }
    return jsonify({'result_hex': out_hex, 'result_bin': out_bin, 'process': process, 'input_info': input_info})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
