from flask import Flask, render_template, request, redirect, url_for, send_from_directory
import cv2
import numpy as np
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from Crypto.Protocol.KDF import PBKDF2
from PIL import Image, ImageDraw
import os

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = 'encrypted'
DECRYPTED_FOLDER = 'decrypted'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ENCRYPTED_FOLDER'] = ENCRYPTED_FOLDER
app.config['DECRYPTED_FOLDER'] = DECRYPTED_FOLDER


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def pad(text):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text) + padder.finalize()
    return padded_data


def encrypt(text, key):
    text = pad(text.encode('utf-8'))
    iv = os.urandom(16)  # Initialization Vector
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_text = encryptor.update(text) + encryptor.finalize()
    return iv + encrypted_text


def text_to_image(encrypted_text, image_path, original_shape):
    header_size = 4  # Using 4 bytes to store the length (adjust as needed)

    # Encode original image shape in header
    shape_info = original_shape[0].to_bytes(2, byteorder='big') + original_shape[1].to_bytes(2, byteorder='big')

    side = int((len(encrypted_text) + header_size + len(shape_info)) ** 0.5) + 1
    image = Image.new("RGB", (side, side), color="white")
    draw = ImageDraw.Draw(image)

    # Store the length and shape in the header
    header_value = len(encrypted_text).to_bytes(header_size, byteorder='big') + shape_info
    for i in range(len(header_value)):
        draw.point((i % side, i // side), fill=(header_value[i], 0, 0))

    for i in range(len(encrypted_text)):
        pixel_value = encrypted_text[i]
        color = (pixel_value, pixel_value, pixel_value)
        draw.point(((i + header_size + len(shape_info)) % side, (i + header_size + len(shape_info)) // side), fill=color)

    image.save(image_path)


def unpad(text):
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(text) + unpadder.finalize()
    return unpadded_data


def decrypt(encrypted_text, key):
    iv = encrypted_text[:16]
    text = encrypted_text[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(text) + decryptor.finalize()
    return unpad(decrypted_text).decode('utf-8')


def image_to_text(image_path):
    image = Image.open(image_path)

    # Read the length and shape from the header
    header_size = 4
    shape_size = 4
    header_value = bytearray()
    for i in range(header_size + shape_size):
        header_value.append(image.getpixel((i % image.width, i // image.width))[0])

    length = int.from_bytes(header_value[:header_size], byteorder='big')
    shape_info = header_value[header_size:]

    original_shape = (
        int.from_bytes(shape_info[:2], byteorder='big'),
        int.from_bytes(shape_info[2:], byteorder='big')
    )

    encrypted_text = bytearray()

    for i in range(length):
        x = (i + header_size + shape_size) % image.width
        y = (i + header_size + shape_size) // image.width

        pixel_value = image.getpixel((x, y))[0]
        encrypted_text.append(pixel_value)

    return bytes(encrypted_text), original_shape


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/encrypt', methods=['POST'])
def encrypt_image():
    if 'file' not in request.files or 'key' not in request.form:
        return redirect(url_for('index'))

    file = request.files['file']
    key = request.form['key']

    if file.filename == '' or not allowed_file(file.filename):
        return redirect(url_for('index'))

    filename = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filename)

    image = cv2.imread(filename)
    image_3d_matrix = np.array(image)
    image_shape = image_3d_matrix.shape
    flattened_pixels = image_3d_matrix.flatten()

    binary_sequence = ''.join(format(pixel, '08b') for pixel in flattened_pixels)

    binary_to_dna_mapping = {'00': 'A', '01': 'T', '10': 'G', '11': 'C'}
    binary_pairs = [binary_sequence[i:i + 2] for i in range(0, len(binary_sequence), 2)]
    dna_sequence = ''.join(binary_to_dna_mapping.get(pair, 'N') for pair in binary_pairs)

    salt = b'Pd\xfc\x92\xe5\xfaR\x84\x0e\x8aL5\xa9\xbf"mr\x96\xd5\tp\xfc\xced\x97&7Do\xf9\x9b\x1a'

    password = key
    encryption_key = PBKDF2(password, salt, dkLen=32, count=100000)

    encrypted_text = encrypt(dna_sequence, encryption_key)
    encrypted_image_path = os.path.join(app.config['ENCRYPTED_FOLDER'], 'encrypted_image.png')
    text_to_image(encrypted_text, encrypted_image_path, image_shape)
    return send_from_directory(app.config['ENCRYPTED_FOLDER'], 'encrypted_image.png', as_attachment=True)

    # return send_from_directory(app.config['ENCRYPTED_FOLDER'], 'encrypted_image.png')


@app.route('/decrypt', methods=['POST'])
def decrypt_image():
    if 'file' not in request.files or 'key' not in request.form:
        return redirect(url_for('index'))

    file = request.files['file']
    key = request.form['key']

    if file.filename == '' or not allowed_file(file.filename):
        return redirect(url_for('index'))

    filename = os.path.join(app.config['ENCRYPTED_FOLDER'], file.filename)
    file.save(filename)

    retrieved_text, original_shape = image_to_text(filename)

    salt = b'Pd\xfc\x92\xe5\xfaR\x84\x0e\x8aL5\xa9\xbf"mr\x96\xd5\tp\xfc\xced\x97&7Do\xf9\x9b\x1a'

    password = key
    decryption_key = PBKDF2(password, salt, dkLen=32, count=100000)

    decrypted_text = decrypt(retrieved_text, decryption_key)
    binary_to_dna_mapping = {'00': 'A', '01': 'T', '10': 'G', '11': 'C'}
    reverse_binary_sequence = ''.join(
    ''.join(key for key, value in binary_to_dna_mapping.items() if value == base)
    for base in decrypted_text
    )
    reconstructed_pixels = np.array([int(reverse_binary_sequence[i:i+8], 2) for i in range(0, len(reverse_binary_sequence), 8)])

    reconstructed_image_3d_matrix = reconstructed_pixels.reshape(original_shape + (3,))
    reconstructed_image_path = os.path.join(app.config['DECRYPTED_FOLDER'], 'decrypted_image.png')
    cv2.imwrite(reconstructed_image_path, reconstructed_image_3d_matrix.astype(np.uint8))
    return send_from_directory(app.config['DECRYPTED_FOLDER'], 'decrypted_image.png', as_attachment=True)

    # return send_from_directory(app.config['DECRYPTED_FOLDER'], 'decrypted_image.png')

from flask import send_from_directory

# Your existing routes...

@app.route('/download/<filename>')
def download(filename):
    return send_from_directory(app.config['ENCRYPTED_FOLDER'], filename)


if __name__ == '__main__':
    app.run(debug=False,host='0.0.0.0')
