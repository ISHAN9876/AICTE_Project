import cv2
import numpy as np
import base64
from encryption import (
    encrypt_symmetric, decrypt_symmetric, encrypt_rsa, decrypt_rsa,
    hash_text, caesar_cipher, affine_cipher, vigenere_cipher, rot13,
    vernam_cipher, feistel_cipher, columnar_cipher, generate_key
)


def encode_message(image, message, key, algorithm):
    if not message:
        return None, "Message cannot be empty."

    # Encryption
    if algorithm in ["AES", "DES", "3DES", "Blowfish"]:
        encrypted_message, status = encrypt_symmetric(message, key, algorithm)
    elif algorithm == "RSA":
        encrypted_message, status = encrypt_rsa(message, key)
    elif algorithm in ["SHA", "MD5", "HMAC"]:
        encrypted_message = hash_text(message, algorithm)
        status = "Message hashed successfully."
    elif algorithm in ["Caesar Cipher", "ROT13"]:
        shift = 13 if algorithm == "ROT13" else 3
        encrypted_message = caesar_cipher(message, shift)
        status = "Message encrypted using Caesar/ROT13."
    elif algorithm == "Affine Cipher":
        encrypted_message = affine_cipher(message, 5, 8)
        status = "Message encrypted using Affine Cipher."
    elif algorithm == "Vigenère Cipher":
        encrypted_message = vigenere_cipher(message, key)
        status = "Message encrypted using Vigenère Cipher."
    elif algorithm == "Vernam Cipher":
        encrypted_message = vernam_cipher(message, key)
        status = "Message encrypted using Vernam Cipher."
    elif algorithm == "Feistel Cipher":
        encrypted_message = feistel_cipher(message, key)
        status = "Message encrypted using Feistel Cipher."
    elif algorithm in ["Single Columnar", "Double Columnar"]:
        encrypted_message = columnar_cipher(message, key, double=(algorithm == "Double Columnar"))
        status = "Message encrypted using Columnar Cipher."
    else:
        return None, "Unsupported encryption algorithm."

    # Convert message to binary
    binary_message = ''.join(format(ord(c), '08b') for c in encrypted_message) + '1111111111111110'  # EOF marker

    # Steganography - Embed binary message into image
    img = image.copy()
    data_index = 0
    total_data = len(binary_message)

    for row in img:
        for pixel in row:
            for channel in range(3):  # RGB channels
                if data_index < total_data:
                    pixel[channel] = (pixel[channel] & ~1) | int(binary_message[data_index])
                    data_index += 1

    return img, status


def decode_message(image, key, algorithm):
    binary_message = ""

    for row in image:
        for pixel in row:
            for channel in range(3):  # Extract LSB from RGB
                binary_message += str(pixel[channel] & 1)

    # Convert binary to text
    message = ""
    for i in range(0, len(binary_message), 8):
        char = chr(int(binary_message[i:i + 8], 2))
        if char == '\xFE':  # EOF marker
            break
        message += char

    # Decryption
    if algorithm in ["AES", "DES", "3DES", "Blowfish"]:
        decrypted_message, status = decrypt_symmetric(message, key, algorithm)
    elif algorithm == "RSA":
        decrypted_message, status = decrypt_rsa(message, key)
    elif algorithm in ["SHA", "MD5", "HMAC"]:
        decrypted_message = message
        status = "Hashes cannot be decrypted."
    elif algorithm in ["Caesar Cipher", "ROT13"]:
        shift = 13 if algorithm == "ROT13" else 3
        decrypted_message = caesar_cipher(message, shift, decrypt=True)
        status = "Message decrypted using Caesar/ROT13."
    elif algorithm == "Affine Cipher":
        decrypted_message = affine_cipher(message, 5, 8, decrypt=True)
        status = "Message decrypted using Affine Cipher."
    elif algorithm == "Vigenère Cipher":
        decrypted_message = vigenere_cipher(message, key, decrypt=True)
        status = "Message decrypted using Vigenère Cipher."
    elif algorithm == "Vernam Cipher":
        decrypted_message = vernam_cipher(message, key, decrypt=True)
        status = "Message decrypted using Vernam Cipher."
    elif algorithm == "Feistel Cipher":
        decrypted_message = feistel_cipher(message, key, decrypt=True)
        status = "Message decrypted using Feistel Cipher."
    elif algorithm in ["Single Columnar", "Double Columnar"]:
        decrypted_message = columnar_cipher(message, key, double=(algorithm == "Double Columnar"), decrypt=True)
        status = "Message decrypted using Columnar Cipher."
    else:
        return "Unsupported decryption algorithm."

    return decrypted_message, status
