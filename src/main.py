import streamlit as st
import cv2
import numpy as np
from Crypto.Cipher import AES, DES
import base64
import os
from io import BytesIO
from PIL import Image


def generate_key(algorithm):
    if algorithm == "AES":
        return os.urandom(16)  # 16-byte key
    elif algorithm == "DES":
        return os.urandom(8)  # 8-byte key


def encrypt_message(message, key, algorithm):
    cipher = AES.new(key, AES.MODE_ECB) if algorithm == "AES" else DES.new(key, DES.MODE_ECB)
    message = message.ljust((len(message) // 16 + 1) * 16)  # Padding for AES/DES
    encrypted = cipher.encrypt(message.encode('utf-8'))
    return base64.b64encode(encrypted).decode()


def decrypt_message(encrypted_message, key, algorithm):
    cipher = AES.new(key, AES.MODE_ECB) if algorithm == "AES" else DES.new(key, DES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(encrypted_message)).decode().strip()
    return decrypted


def encode_image(image, message):
    encoded_image = image.copy()
    message += "::END"  # End delimiter
    binary_message = ''.join(format(ord(c), '08b') for c in message)
    index = 0
    for i in range(image.shape[0]):
        for j in range(image.shape[1]):
            if index < len(binary_message):
                encoded_image[i, j, 0] = (image[i, j, 0] & 254) | int(binary_message[index])
                index += 1
            else:
                break
    return encoded_image


def decode_image(image):
    binary_message = ""
    for i in range(image.shape[0]):
        for j in range(image.shape[1]):
            binary_message += str(image[i, j, 0] & 1)
    message = ''.join(chr(int(binary_message[i:i + 8], 2)) for i in range(0, len(binary_message), 8))
    return message.split("::END")[0]


def main():
    st.set_page_config(page_title="Steganography App", layout="wide")
    st.markdown("""
        <video autoplay loop muted playsinline style="position: fixed; right: 0; bottom: 0; min-width: 100%; min-height: 100%;">
            <source src="https://videos.pexels.com/video-files/3130284/3130284-uhd_3840_2160_30fps.mp4" type="video/mp4">
        </video>
        <style>
            body {background: transparent;}
        </style>
    """, unsafe_allow_html=True)

    st.title("🔒 Steganography Tool")
    option = st.radio("Select an option:", ["Encode", "Decode"])
    algorithm = st.selectbox("Select Algorithm:", ["AES", "DES"])
    key_option = st.radio("Key Option:", ["Auto Generate Key", "Custom Key"])

    if key_option == "Auto Generate Key":
        key = generate_key(algorithm)
    else:
        key = st.text_input("Enter your custom key (16 chars for AES, 8 chars for DES):").encode()

    if key:
        st.write("Your Key:", key.hex())

    if option == "Encode":
        message = st.text_area("Enter message to encode:")
        uploaded_image = st.file_uploader("Upload an image", type=["png", "jpg", "jpeg"])
        if uploaded_image and message:
            image = np.array(Image.open(uploaded_image))
            encrypted_message = encrypt_message(message, key, algorithm)
            encoded_img = encode_image(image, encrypted_message)
            encoded_pil = Image.fromarray(encoded_img)
            buf = BytesIO()
            encoded_pil.save(buf, format="PNG")
            st.download_button("Download Encoded Image", buf.getvalue(), file_name="encoded_image.png",
                               mime="image/png")

    elif option == "Decode":
        uploaded_image = st.file_uploader("Upload an encoded image", type=["png", "jpg", "jpeg"])
        if uploaded_image:
            image = np.array(Image.open(uploaded_image))
            extracted_message = decode_image(image)
            decrypted_message = decrypt_message(extracted_message, key, algorithm)
            st.success(f"Decoded Message: {decrypted_message}")


if __name__ == "__main__":
    main()
