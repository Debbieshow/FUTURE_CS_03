import os
import io
from flask import Flask, request, send_file, render_template
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)

# --- CONFIGURATION ---
# This ensures the vault folder is always found inside your project folder
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'vault')
SECRET_KEY = b'SixteenByteKey!!' # Must be exactly 16, 24, or 32 bytes

# Create the vault folder if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "No file part", 400
   
    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400

    # 1. Read the original data
    data = file.read()
   
    # 2. Setup AES Encryption (CBC Mode)
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC)
   
    # 3. Encrypt the data with padding
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
   
    # 4. Save the IV + Ciphertext together in the vault
    file_path = os.path.join(UPLOAD_FOLDER, f"{file.filename}.enc")
    with open(file_path, "wb") as f:
        f.write(cipher.iv)  # Write the 16-byte IV first
        f.write(ct_bytes)   # Then write the encrypted data
   
    return f"File '{file.filename}' encrypted and saved in the vault!"

@app.route('/download/<filename>')
def download_file(filename):
    # 1. Look for the encrypted version
    enc_path = os.path.join(UPLOAD_FOLDER, f"{filename}.enc")
   
    if not os.path.exists(enc_path):
        return f"Error: {filename}.enc not found in vault.", 404

    with open(enc_path, "rb") as f:
        # 2. Read the first 16 bytes to get the IV
        iv = f.read(16)
        encrypted_data = f.read()

    # 3. Setup Decryption
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
   
    # 4. Decrypt and strip padding
    try:
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    except ValueError:
        return "Decryption failed: Incorrect padding or key.", 500

    # 5. Send decrypted file back to browser
    return send_file(
        io.BytesIO(decrypted_data),
        download_name=filename,
        as_attachment=True
    )

if __name__ == '__main__':
    print(f"Vault location: {UPLOAD_FOLDER}")
    app.run(port=5000, debug=True)
