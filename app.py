from flask import Flask, render_template, request
import hashlib
import os

app = Flask(__name__)

# Fungsi Inti: Hashing SHA-256 dengan mekanisme Salt
# Sesuai prinsip One-Way Function: hasil hash tidak bisa dikembalikan ke teks asli
def hash_password(password, salt=None):
    if salt is None:
        # Generate salt acak 16 byte (32 karakter hex) 
        # Peran Salt: Menghindari serangan Rainbow Table dengan membuat hash unik
        salt = os.urandom(16).hex()
    
    # Gabungkan salt dan password sebelum di-hash
    # Urutan: SALT + PASSWORD
    salted_password = salt + password
    
    # Proses Hashing menggunakan algoritma SHA-256
    hash_obj = hashlib.sha256(salted_password.encode())
    hashed_result = hash_obj.hexdigest()
    
    return hashed_result, salt

@app.route('/', methods=['GET', 'POST'])
def index():
    generated_hash = None
    generated_salt = None
    verify_result = None
    input_text = ""

    if request.method == 'POST':
        # --- LOGIKA TOMBOL GENERATE ---
        if 'generate' in request.form:
            # Mengambil input dan membersihkan spasi liar di ujung teks
            input_text = (request.form.get('text_to_hash') or "").strip()
            if input_text:
                generated_hash, generated_salt = hash_password(input_text)

        # --- LOGIKA TOMBOL VERIFY ---
        elif 'verify' in request.form:
            # Mengambil data dari form verifikasi
            # Gunakan .strip() pada semua input untuk memastikan tidak ada spasi/newline yang terbawa
            provided_hash = (request.form.get('hash_to_verify') or "").strip()
            provided_salt = (request.form.get('salt_to_verify') or "").strip()
            original_text = (request.form.get('original_text') or "").strip()
            
            if original_text and provided_salt:
                # Lakukan hashing ulang pada teks asli dengan salt yang diberikan
                check_hash, _ = hash_password(original_text, provided_salt)
                
                # Bandingkan hasil hash baru dengan hash yang di-paste user
                if check_hash.lower() == provided_hash.lower():
                    verify_result = "Match"
                else:
                    verify_result = "Not Match"
            else:
                # Jika ada kolom yang kosong saat verifikasi
                verify_result = "Not Match"

    return render_template('index.html', 
                           generated_hash=generated_hash, 
                           generated_salt=generated_salt,
                           verify_result=verify_result,
                           input_text=input_text)

if __name__ == '__main__':
    # Menjalankan server Flask dalam mode debug agar mudah memantau error
    app.run(debug=True)