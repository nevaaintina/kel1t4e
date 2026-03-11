from flask import Flask, render_template, request
import hashlib
import os
import re
import time

app = Flask(__name__)

# Fitur 5: Input Sanitization
def sanitize_input(text):
    return re.sub(r'[^\w\s]', '', text)

# Fitur 4: Multi-SHA dengan Custom Rounds (Iterasi)
def hash_with_rounds(password, salt, algo='sha256', rounds=1):
    data = (salt + password).encode()
    
    # Pilih fungsi hash dari hashlib
    hash_func = getattr(hashlib, algo)
    
    # Melakukan iterasi sebanyak jumlah rounds
    current_hash = hash_func(data).digest()
    for _ in range(rounds - 1):
        current_hash = hash_func(current_hash).digest()
        
    return current_hash.hex()

@app.route('/', methods=['GET', 'POST'])
def index():
    gen_hash = None
    gen_salt = None
    gen_algo = 'sha256'
    gen_rounds = 10
    exec_time = 0
    verify_result = None
    
    prev = {'hash': '', 'salt': '', 'orig': '', 'algo': 'sha256'}

    if request.method == 'POST':
        if 'generate' in request.form:
            start_time = time.time()
            raw_input = request.form.get('text_to_hash', '').strip()
            gen_algo = request.form.get('algo_selection', 'sha256')
            gen_rounds = int(request.form.get('rounds_selection', 10))
            clean_input = sanitize_input(raw_input)
            
            if clean_input:
                gen_salt = os.urandom(16).hex()
                gen_hash = hash_with_rounds(clean_input, gen_salt, gen_algo, gen_rounds)
                exec_time = round((time.time() - start_time) * 1000, 2)

        elif 'verify' in request.form:
            v_hash = request.form.get('hash_to_verify', '').strip()
            v_salt = request.form.get('salt_to_verify', '').strip()
            v_orig = sanitize_input(request.form.get('original_text', '').strip())
            v_algo = request.form.get('algo_verify_selection', 'sha256')
            v_rounds = int(request.form.get('v_rounds_hidden', 10))
            
            prev = {'hash': v_hash, 'salt': v_salt, 'orig': v_orig, 'algo': v_algo}

            if v_orig and v_salt:
                check = hash_with_rounds(v_orig, v_salt, v_algo, v_rounds)
                verify_result = "Match" if check.lower() == v_hash.lower() else "Not Match"

    # PERBAIKAN DI SINI: Menggunakan '=' bukan '-'
    return render_template('index.html', 
                           gen_hash=gen_hash, 
                           gen_salt=gen_salt, 
                           gen_algo=gen_algo, 
                           gen_rounds=gen_rounds,
                           exec_time=exec_time, 
                           res=verify_result, 
                           prev=prev)

# Penting untuk Vercel
app = app 

if __name__ == '__main__':
    app.run(debug=True)