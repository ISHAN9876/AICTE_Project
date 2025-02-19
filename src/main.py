import streamlit as st
import cv2
import numpy as np
import base64
import hashlib
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
import os
import random
import string


# === Generate Key Functions ===
def generate_random_key(algorithm):
    """Generates a secure random key based on the selected algorithm."""
    if algorithm == "AES":
        return ''.join(random.choices(string.ascii_letters + string.digits, k=32))  # 256-bit key
    elif algorithm == "DES":
        return ''.join(random.choices(string.ascii_letters + string.digits, k=8))  # 64-bit key


def hash_key(key, algorithm):
    """Hashes the key appropriately for AES or DES."""
    if algorithm == "AES":
        return hashlib.sha256(key.encode()).digest()  # 256-bit key for AES
    elif algorithm == "DES":
        return hashlib.md5(key.encode()).digest()[:8]  # 64-bit key for DES


# === Encryption & Decryption ===
def encrypt_message(message, key, algorithm):
    """Encrypts the message using AES or DES."""
    hashed_key = hash_key(key, algorithm)
    if algorithm == "AES":
        cipher = AES.new(hashed_key, AES.MODE_CBC)
    else:  # DES
        cipher = DES.new(hashed_key, DES.MODE_CBC)

    encrypted = cipher.encrypt(pad(message.encode(), cipher.block_size))
    return base64.b64encode(cipher.iv + encrypted).decode()


def decrypt_message(encrypted_message, key, algorithm):
    """Decrypts an AES or DES encrypted message."""
    try:
        hashed_key = hash_key(key, algorithm)
        data = base64.b64decode(encrypted_message)
        iv = data[:16] if algorithm == "AES" else data[:8]
        encrypted = data[len(iv):]

        if algorithm == "AES":
            cipher = AES.new(hashed_key, AES.MODE_CBC, iv)
        else:  # DES
            cipher = DES.new(hashed_key, DES.MODE_CBC, iv)

        return unpad(cipher.decrypt(encrypted), cipher.block_size).decode()
    except:
        return "Authentication failed! Incorrect key."


# === Encoding & Decoding Messages in Images ===
def encode_message(img, message, key, algorithm):
    """Encodes an encrypted message into an image using LSB."""
    encrypted_message = encrypt_message(message, key, algorithm) + "%%"
    binary_message = ''.join(format(ord(c), '08b') for c in encrypted_message)
    img_flat = img.flatten()

    if len(binary_message) > len(img_flat):
        return None, "Message is too long for this image!"

    for i in range(len(binary_message)):
        img_flat[i] = (img_flat[i] & 254) | int(binary_message[i])

    img_encoded = img_flat.reshape(img.shape)
    return img_encoded, "Message encrypted successfully!"


def decode_message(img, key, algorithm):
    """Extracts and decrypts the hidden message from an image."""
    img_flat = img.flatten()
    binary_message = ''.join(str(img_flat[i] & 1) for i in range(len(img_flat)))
    chars = [chr(int(binary_message[i:i + 8], 2)) for i in range(0, len(binary_message), 8)]
    extracted_message = ''.join(chars)

    if "%%" not in extracted_message:
        return "No hidden message found."

    extracted_message = extracted_message.split("%%")[0]
    return decrypt_message(extracted_message, key, algorithm)


# === Streamlit UI ===
st.markdown("""
    <video autoplay loop muted playsinline style="position: fixed; right: 0; bottom: 0; min-width: 100%; min-height: 100%;">
        <source src="https://videos.pexels.com/video-files/3130284/3130284-uhd_3840_2160_30fps.mp4" type="video/mp4">
    </video>
""", unsafe_allow_html=True)

st.title("🔒 Image-Based Steganography Tool")
option = st.radio("Select an option", ("Encode Message", "Decode Message"))

if option == "Encode Message":
    uploaded_file = st.file_uploader("Upload an Image (PNG only)", type=["png"])
    if uploaded_file:
        image = cv2.imdecode(np.frombuffer(uploaded_file.read(), np.uint8), cv2.IMREAD_COLOR)
        message = st.text_area("Enter your secret message")
        algorithm = st.radio("Choose Encryption Algorithm", ("AES", "DES"))

        use_custom_key = st.checkbox("Use Custom Key?")
        if use_custom_key:
            key = st.text_input("Enter Encryption Key", type="password")
        else:
            key = generate_random_key(algorithm)
            st.text(f"Generated Key: {key}")

        if st.button("Encode & Save Image"):
            encoded_img, status = encode_message(image, message, key, algorithm)
            if encoded_img is not None:
                cv2.imwrite("encoded_image.png", encoded_img)
                st.success(status)
                with open("encoded_image.png", "rb") as file:
                    st.download_button("Download Encrypted Image", file, "encoded_image.png")
            else:
                st.error(status)

elif option == "Decode Message":
    uploaded_file = st.file_uploader("Upload an Encrypted Image", type=["png"])
    if uploaded_file:
        image = cv2.imdecode(np.frombuffer(uploaded_file.read(), np.uint8), cv2.IMREAD_COLOR)
        algorithm = st.radio("Choose Encryption Algorithm", ("AES", "DES"))
        key = st.text_input("Enter Decryption Key", type="password")

        if st.button("Decode Message"):
            decrypted_message = decode_message(image, key, algorithm)
            st.success(f"Decrypted Message: {decrypted_message}")

