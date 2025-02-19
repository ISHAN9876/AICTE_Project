# 🔒 AICTE Project - Image-Based Steganography Tool
![Image](https://github.com/user-attachments/assets/d333da07-d335-4ad2-b1cc-fa05751cb183)


## 📌 Overview

This project is part of the **AICTE-IBM-EDUNET INTERNSHIP**, providing a **Steganography Tool** built using **Streamlit**, allowing users to securely hide messages inside images. The messages are **encrypted using AES or DES** before being embedded, ensuring an extra layer of security.


---

## ✨ Features

✅ **Encrypt Messages in Images** - Users can encode messages inside images using AES or DES.
✅ **Decrypt Messages from Images** - Retrieve hidden messages securely.
✅ **Custom or Auto-Generated Key** - Users can enter a custom encryption key or use an automatically generated one.
✅ **Download Encoded Image** - Users can download the modified image with the hidden message.
✅ **User-Friendly UI** - Built with **Streamlit** for an interactive experience.
✅ **Looping Video Background** - Uses a high-quality looping background video for aesthetics.

---

## 📂 Project Structure

```
📁 AICTE_Project
│── .idea                  # Project settings
│── src                    # Source code directory
│── AICTE PROJECT PPT.pptx # Project presentation file
│── README.md              # Project documentation
│── encoded_image.png      # Example of encoded image
│── requirements.txt       # Dependencies file
```

---

## 🚀 Installation & Setup

### **1️⃣ Clone the Repository**

```bash
git clone https://github.com/ISHAN9876/AICTE_Project.git
cd AICTE_Project
```

### **2️⃣ Install Dependencies**

Ensure you have Python installed, then run:

```bash
pip install -r requirements.txt
```

### **3️⃣ Run the Application**

```bash
streamlit run app.py
```

This will launch the application in your web browser.

---

## 🛠 Usage Guide

### **Encoding a Message**

1️⃣ Upload a PNG image.
2️⃣ Enter the secret message.
3️⃣ Select **AES** or **DES** encryption.
4️⃣ Choose to use a **custom key** or let the app generate one.
5️⃣ Click **Encode & Save Image**.
6️⃣ Download the encoded image.

### **Decoding a Message**

1️⃣ Upload the encoded PNG image.
2️⃣ Enter the **correct key**.
3️⃣ Select the encryption algorithm used.
4️⃣ Click **Decode Message** to reveal the secret.

---

## 🔧 Dependencies

- `streamlit`
- `opencv-python`
- `numpy`
- `pycryptodome`

Install all dependencies using:

```bash
pip install -r requirements.txt
```

---

## 🎥 Background Video

This project features a **looping high-quality background video** sourced from **Pexels**:
[Video Link](https://videos.pexels.com/video-files/3130284/3130284-uhd_3840_2160_30fps.mp4)

---

## 📜 License

This project is open-source under the **MIT License**. Feel free to modify and use it!

---

## 👨‍💻 Author

Developed by **Ishan**

- GitHub: [ISHAN9876](https://github.com/ISHAN9876)
- LinkedIn: [LinkedIn](www.linkedin.com/in/ishankumra)
- Email: [ishankumra13579@gmail.com](mailto\:ishankumra13579@gmail.com)

---

## ⭐ Contributions

Feel free to **fork this repository**, open issues, or submit pull requests to improve the project.

## Future Scope 
 I would be adding more features to this app , some which are decided are :
       - Support for more image formats
       - Steganography for videos
       - Encryption/Decryption Algorithms so that user has more options for encoding/decoding
       - Providing users a secure channel for efficient and safe key management
🚀 **Happy Coding!** 🔥

