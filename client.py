# # File dari sisi client 
# # Berfungsi untuk generate Key dan Membuat Signature untuk testing di Swagger UI

# from cryptography.hazmat.primitives.asymmetric import ed25519
# from cryptography.hazmat.primitives import serialization
# import os

# # Nama file untuk output kunci client
# CLIENT_PRIV_FILE = "client_priv.pem"
# CLIENT_PUB_FILE = "client_pub.pem"

# def generate_keys():
#     """
#     Fungsi untuk membuat pasangan kunci Ed25519 baru.
#     Kunci ini lebih modern dan ringkas dibanding RSA/EC biasa.
#     """
#     print("[-] Sedang membuat kunci baru...")
    
#     # 1. Generate Private Key
#     priv_key = ed25519.Ed25519PrivateKey.generate()
    
#     # 2. Turunkan Public Key dari Private Key
#     pub_key = priv_key.public_key()

#     # 3. Simpan Private Key ke file (PEM)
#     # Penting: Private key tidak dienkripsi password agar mudah untuk testing tugas
#     with open(CLIENT_PRIV_FILE, "wb") as f:
#         f.write(priv_key.private_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PrivateFormat.PKCS8,
#             encryption_algorithm=serialization.NoEncryption()
#         ))

#     # 4. Simpan Public Key ke file (PEM) -> File ini nanti diupload ke Swagger /store
#     with open(CLIENT_PUB_FILE, "wb") as f:
#         f.write(pub_key.public_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PublicFormat.SubjectPublicKeyInfo
#         ))

#     print(f"[+] Kunci berhasil dibuat!")
#     print(f"    - Private Key: {CLIENT_PRIV_FILE} (JANGAN DISEBAR)")
#     print(f"    - Public Key : {CLIENT_PUB_FILE} (Upload ini ke /store)")
    
#     return priv_key, pub_key

# def sign_message(private_key, message: str):
#     """
#     Fungsi untuk menandatangani pesan menggunakan Private Key.
#     Outputnya adalah signature dalam format HEX (supaya mudah dicopy ke Swagger).
#     """
#     message_bytes = message.encode('utf-8')
#     signature = private_key.sign(message_bytes)
#     return signature.hex()

# # --- Main Program ---
# if __name__ == "__main__":
#     # 1. Load/Buat Key
#     if not os.path.exists(CLIENT_PRIV_FILE):
#         priv_key, pub_key = generate_keys()
#     else:
#         print("[*] Meload kunci yang sudah ada...")
#         with open(CLIENT_PRIV_FILE, "rb") as f:
#             priv_key = serialization.load_pem_private_key(f.read(), password=None)

#     nama_pengirim = "Dr. Vegapunk"

#     # ==========================================
#     # AREA SIMULASI PESAN (Ubah-ubah di sini)
#     # ==========================================
#     nama_pengirim = "Argya"  # Sesuaikan dengan nama yang kamu input di /store
#     pesan_rahasia = "Data penelitian di Lab 5 aman."

#     # 2. Buat Signature
#     signature_hex = sign_message(priv_key, pesan_rahasia)

#     # 3. Cetak output untuk dicopy ke Swagger UI
#     print("\n" + "="*50)
#     print("   DATA UNTUK TESTING SWAGGER UI")
#     print("="*50)
#     print(f"1. Endpoint : /store (Upload Public Key)")
#     print(f"   - Username : {nama_pengirim}")
#     print(f"   - File     : {CLIENT_PUB_FILE} (Cari file ini di folder project)")
#     print("-" * 50)
#     print(f"2. Endpoint : /verify atau /relay")
#     print(f"   - Sender   : {nama_pengirim}")
#     print(f"   - Message  : {pesan_rahasia}")
#     print(f"   - Signature: {signature_hex}")
#     print("="*50)
#     print("Copy 'Signature' di atas (tanpa kutip) dan paste ke kolom signature_hex di Swagger.")
# File Client Simulator untuk Project Keamanan Informasi
# Support: Level B (Signature) & Level A (Secure Session/JWT)

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import os

def get_user_keys(username):
    """
    Mencari kunci berdasarkan username.
    - Jika file kunci ada: Load kunci tersebut.
    - Jika tidak ada: Bikin baru dan simpan dengan nama {username}_priv.pem.
    """
    priv_file = f"{username}_priv.pem"
    pub_file = f"{username}_pub.pem"
    
    # 1. Cek apakah kunci sudah ada di folder?
    if os.path.exists(priv_file):
        print(f"[*] File kunci untuk user '{username}' DITEMUKAN. Memuat identitas lama...")
        with open(priv_file, "rb") as f:
            priv_key = serialization.load_pem_private_key(f.read(), password=None)
        is_new_user = False
    
    # 2. Jika belum ada, buat baru
    else:
        print(f"[-] File kunci untuk user '{username}' TIDAK ADA. Membuat identitas BARU...")
        priv_key = ed25519.Ed25519PrivateKey.generate()
        pub_key = priv_key.public_key()
        
        # Simpan Private Key
        with open(priv_file, "wb") as f:
            f.write(priv_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Simpan Public Key
        with open(pub_file, "wb") as f:
            f.write(pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        is_new_user = True

    return priv_key, pub_file, is_new_user

def sign_message(private_key, message: str):
    """Menandatangani pesan string dan mengembalikan Hex Signature"""
    message_bytes = message.encode('utf-8')
    signature = private_key.sign(message_bytes)
    return signature.hex()

# --- MAIN PROGRAM INTERAKTIF ---
if __name__ == "__main__":
    print("\n" + "="*60)
    print("   CLIENT SIMULATOR - PUNK RECORDS (MULTIUSER & JWT READY)")
    print("="*60)
    
    # 1. Input Identitas
    target_user = input(">> Masukkan Username Anda (cth: argya): ").strip()
    if not target_user: target_user = "argya" # Default kalau kosong
    
    # 2. Load/Generate Kunci
    priv_key, pub_filename, is_new = get_user_keys(target_user)
    
    print("-" * 60)
    
    # 3. Logika Upload Key (Level B)
    if is_new:
        print("!!! PERHATIAN: INI ADALAH USER BARU !!!")
        print(f"Langkah Wajib Pertama:")
        print(f"1. Buka Swagger -> Endpoint /store")
        print(f"2. Username : {target_user}")
        print(f"3. File     : Upload file '{pub_filename}' (ada di folder project)")
        print(f"4. Execute!")
    else:
        print("(User lama terdeteksi. Tidak perlu upload ke /store lagi jika sudah pernah.)")
        
    print("-" * 60)

    # 4. Generate Data Login (Level A)
    # Server api.py mengharuskan pesan login adalah "LOGIN_ACTION"
    pesan_login = "LOGIN_ACTION"
    signature_login = sign_message(priv_key, pesan_login)
    
    print("\n[ DATA UNTUK LOGIN (LEVEL A - Secure Session) ]")
    print("Gunakan data ini di endpoint '/login' untuk dapat Token:")
    print(f" > username      : {target_user}")
    print(f" > signature_hex : {signature_login}")
    print("\n>>> CARA PAKAI:")
    print("    1. Paste data di atas ke /login -> Execute.")
    print("    2. Copy 'access_token' dari respon server.")
    print("    3. Klik tombol gembok (Authorize) di atas kanan Swagger.")
    print("    4. Paste token -> Authorize -> Close.")
    
    # 5. Generate Data Pesan Biasa (Opsional / Level B+)
    print("\n" + "-"*60)
    print("[ DATA UNTUK KIRIM PESAN (LEVEL B+ atau TEST MANUAL) ]")
    pesan_custom = input(">> Tulis pesan rahasia yang mau dikirim (Enter untuk skip): ")
    
    if pesan_custom:
        sig_custom = sign_message(priv_key, pesan_custom)
        print(f"\nData untuk endpoint '/verify' atau '/relay' (jika tanpa token):")
        print(f" > sender        : {target_user}")
        print(f" > message       : {pesan_custom}")
        print(f" > signature_hex : {sig_custom}")
        print("\n*Catatan: Jika sudah pakai Token (Level A), endpoint /relay hanya butuh 'recipient' & 'message'.")
    
    print("="*60 + "\n")