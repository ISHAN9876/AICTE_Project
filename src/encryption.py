import hashlib
import hmac
import random
import string
from Crypto.Cipher import AES, DES, DES3, Blowfish
from Crypto.PublicKey import RSA, ECC
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import numpy as np

# Key Generation Function
def generate_key(algorithm):
    if algorithm in ["AES", "DES", "3DES", "Blowfish"]:
        key_size = {"AES": 16, "DES": 8, "3DES": 16, "Blowfish": 16}[algorithm]
        return get_random_bytes(key_size).hex()
    elif algorithm == "RSA":
        key = RSA.generate(2048)
        return key.export_key().decode()
    elif algorithm == "ECC":
        key = ECC.generate(curve="P-256")
        return key.export_key(format="PEM")
    elif algorithm in ["SHA", "MD5", "HMAC"]:
        return ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    else:
        return ''.join(random.choices(string.ascii_uppercase, k=10))  # For classical ciphers

# Symmetric Encryption Functions

def encrypt_symmetric(plaintext, key, algorithm):
    key = bytes.fromhex(key)
    iv = get_random_bytes(16)

    if algorithm == "AES":
        cipher = AES.new(key, AES.MODE_CBC, iv)
    elif algorithm == "DES":
        cipher = DES.new(key[:8], DES.MODE_CBC, iv[:8])
    elif algorithm == "3DES":
        cipher = DES3.new(key, DES3.MODE_CBC, iv[:8])
    elif algorithm == "Blowfish":
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv[:8])
    else:
        return None, "Invalid algorithm."

    encrypted = cipher.encrypt(pad(plaintext.encode(), cipher.block_size))
    return base64.b64encode(iv + encrypted).decode(), "Encryption Successful"

def decrypt_symmetric(ciphertext, key, algorithm):
    key = bytes.fromhex(key)
    data = base64.b64decode(ciphertext)
    iv, encrypted = data[:16], data[16:]

    if algorithm == "AES":
        cipher = AES.new(key, AES.MODE_CBC, iv)
    elif algorithm == "DES":
        cipher = DES.new(key[:8], DES.MODE_CBC, iv[:8])
    elif algorithm == "3DES":
        cipher = DES3.new(key, DES3.MODE_CBC, iv[:8])
    elif algorithm == "Blowfish":
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv[:8])
    else:
        return None, "Invalid algorithm."

    decrypted = unpad(cipher.decrypt(encrypted), cipher.block_size)
    return decrypted.decode(), "Decryption Successful"

# Asymmetric Encryption Functions (RSA)
from Crypto.PublicKey import RSA

# RSA Key Generation
def rsa_generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key().decode()
    public_key = key.publickey().export_key().decode()
    return private_key, public_key

def encrypt_rsa(plaintext, public_key):
    key = RSA.import_key(public_key)
    encrypted = key.publickey().encrypt(plaintext.encode(), None)[0]
    return base64.b64encode(encrypted).decode(), "RSA Encryption Successful"

def decrypt_rsa(ciphertext, private_key):
    key = RSA.import_key(private_key)
    decrypted = key.decrypt(base64.b64decode(ciphertext))
    return decrypted.decode(), "RSA Decryption Successful"

# Hashing & HMAC Functions
def hash_text(text, algorithm):
    if algorithm == "SHA":
        return hashlib.sha256(text.encode()).hexdigest()
    elif algorithm == "MD5":
        return hashlib.md5(text.encode()).hexdigest()
    elif algorithm == "HMAC":
        secret = b'secret_key'
        return hmac.new(secret, text.encode(), hashlib.sha256).hexdigest()
    else:
        return "Invalid Hash Algorithm"

# Classical Cipher Implementations
def caesar_cipher(text, shift, decrypt=False):
    shift = -shift if decrypt else shift
    result = ''.join(
        chr((ord(c) - ord('A' if c.isupper() else 'a') + shift) % 26 + ord('A' if c.isupper() else 'a'))
        if c.isalpha() else c
        for c in text
    )
    return result

def affine_cipher(text, a, b, decrypt=False):
    m = 26
    mod_inverse = pow(a, -1, m) if decrypt else 1
    result = ''.join(
        chr(((ord(c) - ord('A')) * mod_inverse - b) % m + ord('A')) if decrypt
        else chr(((ord(c) - ord('A')) * a + b) % m + ord('A')) if c.isupper() else c
        for c in text
    )
    return result

def vigenere_cipher(text, key, decrypt=False):
    key = key.upper()
    key_length = len(key)
    result = []
    for i, c in enumerate(text):
        shift = ord(key[i % key_length]) - ord('A')
        result.append(caesar_cipher(c, shift, decrypt))
    return ''.join(result)

def rot13(text):
    return caesar_cipher(text, 13)

# Columnar Transposition Ciphers
def columnar_cipher(text, key, double=False, decrypt=False):
    num_cols = len(key)
    sorted_key = sorted((e, i) for i, e in enumerate(key))
    if not decrypt:
        grid = [text[i:i+num_cols] for i in range(0, len(text), num_cols)]
        sorted_cols = [''.join(grid[j][i] for j in range(len(grid)) if i < len(grid[j])) for _, i in sorted_key]
        return ''.join(sorted_cols)
    else:
        num_rows = len(text) // num_cols
        cols = [text[i*num_rows:(i+1)*num_rows] for _, i in sorted_key]
        return ''.join(''.join(cols[i][j] for i in range(len(cols))) for j in range(num_rows))

# Vernam Cipher (One-Time Pad)
def vernam_cipher(text, key, decrypt=False):
    return ''.join(chr(ord(t) ^ ord(k)) for t, k in zip(text, key))

# Feistel Cipher Implementation
def feistel_cipher(text, key, decrypt=False):
    rounds = 4
    keys = [key[i % len(key)] for i in range(rounds)]
    left, right = text[:len(text)//2], text[len(text)//2:]
    for k in (reversed(keys) if decrypt else keys):
        new_left = right
        right = ''.join(chr(ord(l) ^ ord(k)) for l in left)
        left = new_left
    return left + right
