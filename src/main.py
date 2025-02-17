import streamlit as st
from src.ui import main

st.markdown(
    """
    <style>
        .stApp {
            background: url('https://videos.pexels.com/video-files/3130284/3130284-uhd_3840_2160_30fps.mp4') no-repeat center center fixed;
            background-size: cover;
        }
    </style>
    """,
    unsafe_allow_html=True
)

if __name__ == "__main__":
    main()
