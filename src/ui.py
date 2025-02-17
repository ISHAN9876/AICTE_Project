import streamlit as st
import cv2
import numpy as np
from steganography import encode_message, decode_message
from encryption import generate_key, rsa_generate_keys

# Background Video (Looped)
video_url = "https://videos.pexels.com/video-files/3130284/3130284-uhd_3840_2160_30fps.mp4"
'''st.markdown(
    f"""
    <style>
    .video-container {{
        position: fixed;
        right: 0;
        bottom: 0;
        min-width: 100%;
        min-height: 100%;
        z-index: -1;
    }}
    </style>
    <video class="video-container" autoplay loop muted>
        <source src="{video_url}" type="video/mp4">
    </video>
    """,
    unsafe_allow_html=True
)'''
st.markdown(
    """
    <video autoplay loop muted plays inline style="position: fixed; width: 100vw; height: 100vh; object-fit: cover; z-index: -1;">
        <source src="https://videos.pexels.com/video-files/3130284/3130284-uhd_3840_2160_30fps.mp4" type="video/mp4">
    </video>
    """,
    unsafe_allow_html=True
)


def main():
    st.title("🔒 Image-Based Secure Data Hiding - Steganography Tool")

    # Select Encoding or Decoding
    option = st.radio("Select an option", ("Encode Message", "Decode Message"))


    # Encryption Algorithm Selection

    algorithms = [
        "AES", "DES", "3DES", "ChaCha20", "Blowfish", "RSA", "SHA", "MD5", "HMAC",
        "Rail Fence", "Single Columnar", "Double Columnar", "ECC", "Caesar Cipher",
        "Hill Cipher", "Playfair Cipher", "ROT13", "Affine Cipher", "Feistel Cipher",
        "Vigenère Cipher", "Vernam Cipher"
    ]
    # Encryption Algorithm Selection
    algorithm = st.selectbox("Select Encryption Algorithm", algorithms)

    key_option = st.selectbox("Key Generation Mode", ["Auto Key", "User-entered Custom Key", "Auto-Generated Editable Key"])

    if key_option == "Auto Key":
        key = generate_key("AES")  # Default to AES key generation
        st.write(f"🔑 **Generated Key:** `{key}`")  # Display the generated key
    elif key_option == "User-entered Custom Key":
        key = st.text_input("Enter your custom key", type="password")
    else:
        if "generated_key" not in st.session_state:
            st.session_state.generated_key = generate_key("AES")  # Generate AES key by default
        key = st.text_area("Generated Key (Editable)", value=st.session_state.generated_key)
        if st.button("🔄 Regenerate Key"):
            st.session_state.generated_key = generate_key("AES")
            st.rerun()

    # Encode Message Section
    if option == "Encode Message":
        uploaded_file = st.file_uploader("📤 Upload an Image (JPG only)", type=["jpg"])

        if uploaded_file:
            image = cv2.imdecode(np.frombuffer(uploaded_file.read(), np.uint8), cv2.IMREAD_COLOR)
            message = st.text_area("📝 Enter your secret message")
            algorithm = st.selectbox("🔐 Select Encryption Algorithm", algorithms)

            if st.button("🚀 Encode & Save Image"):
                encoded_img, status = encode_message(image, message, key, algorithm)
                if encoded_img is not None:
                    cv2.imwrite("stego.jpg", encoded_img)
                    st.success(status)
                    with open("stego.jpg", "rb") as file:
                        st.download_button("📥 Download Encrypted Image", file, "stego.jpg")
                else:
                    st.error(status)

    # Decode Message Section
    elif option == "Decode Message":
        uploaded_file = st.file_uploader("📥 Upload an Encrypted Image", type=["jpg"])

        if uploaded_file:
            image = cv2.imdecode(np.frombuffer(uploaded_file.read(), np.uint8), cv2.IMREAD_COLOR)
            algorithm = st.selectbox("🔓 Select Encryption Algorithm", algorithms)
            key = st.text_input("🔑 Enter decryption key", type="password")  # Key field added for decryption

            if st.button("🔍 Decode Message"):
                decrypted_message, status = decode_message(image, key, algorithm)
                st.success(f"📜 **Decrypted Message:** {decrypted_message}")

if __name__ == "__main__":
    main()
