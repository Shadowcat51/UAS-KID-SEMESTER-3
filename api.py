# # File utama API: Level Stella (A) - Secure Session & JWT
# from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends, status
# from fastapi.middleware.cors import CORSMiddleware
# from fastapi.security import OAuth2PasswordBearer
# from typing import Optional
# import os
# from datetime import datetime, timedelta

# # Import Library Kriptografi
# from cryptography.hazmat.primitives import serialization, hashes
# from cryptography.hazmat.primitives.asymmetric import ec, ed25519
# from cryptography.exceptions import InvalidSignature

# # Import Library JWT
# from jose import JWTError, jwt

# app = FastAPI(title="Security Service", version="1.0.0")

# # --- KONFIGURASI JWT ---
# SECRET_KEY = "rahasia_dapur_vegapunk_egghead" # Harusnya ditaruh di .env
# ALGORITHM = "HS256"
# ACCESS_TOKEN_EXPIRE_MINUTES = 30

# # Skema Auth untuk Swagger UI (agar muncul tombol gembok 'Authorize')
# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# # Setup Folder Penyimpanan
# STORAGE_DIR = "storage"
# if not os.path.exists(STORAGE_DIR):
#     os.makedirs(STORAGE_DIR)

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# # --- Helper Function Kripto ---
# def load_public_key(username: str):
#     filepath = os.path.join(STORAGE_DIR, f"{username}_pub.pem")
#     if not os.path.exists(filepath):
#         return None
#     with open(filepath, "rb") as key_file:
#         try:
#             return serialization.load_pem_public_key(key_file.read())
#         except Exception:
#             return None

# def load_server_private_key():
#     key_path = "punkhazard-keys/priv.pem" 
#     with open(key_path, "rb") as key_file:
#         return serialization.load_pem_private_key(key_file.read(), password=None)

# # --- Helper Function JWT (Secure Session) ---
# def create_access_token(data: dict):
#     to_encode = data.copy()
#     expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
#     to_encode.update({"exp": expire})
#     encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
#     return encoded_jwt

# async def get_current_user(token: str = Depends(oauth2_scheme)):
#     """
#     Fungsi ini dipanggil otomatis oleh FastAPI untuk memvalidasi Token Bearer.
#     Jika token valid, fungsi ini mengembalikan username pemilik token.
#     """
#     credentials_exception = HTTPException(
#         status_code=status.HTTP_401_UNAUTHORIZED,
#         detail="Could not validate credentials",
#         headers={"WWW-Authenticate": "Bearer"},
#     )
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         username: str = payload.get("sub")
#         if username is None:
#             raise credentials_exception
#     except JWTError:
#         raise credentials_exception
#     return username

# # --- Endpoints ---

# @app.get("/")
# async def get_index():
#     return {"message": "Welcome to Punk Records API v1.0 (Secure)"}

# # 1. Store Public Key (Tetap sama)
# @app.post("/store")
# async def store_pubkey(username: str = Form(...), file: UploadFile = File(...)):
#     try:
#         key_content = await file.read()
#         serialization.load_pem_public_key(key_content) # Validasi
        
#         save_path = os.path.join(STORAGE_DIR, f"{username}_pub.pem")
#         with open(save_path, "wb") as f:
#             f.write(key_content)
            
#         return {"success": True, "message": f"Key {username} saved."}
#     except Exception as e:
#         return {"success": False, "message": str(e)}

# # 2. Login (Mendapatkan Token) - INI YANG BARU
# @app.post("/login")
# async def login(username: str = Form(...), signature_hex: str = Form(...)):
#     """
#     User login dengan menandatangani pesan khusus 'LOGIN_ACTION'.
#     Jika signature valid -> Dapat Token JWT.
#     """
#     # Pesan yang wajib ditandatangani untuk login
#     LOGIN_MESSAGE = "LOGIN_ACTION" 

#     public_key = load_public_key(username)
#     if not public_key:
#         raise HTTPException(status_code=404, detail="User not found.")

#     # Verifikasi Signature
#     try:
#         sig_bytes = bytes.fromhex(signature_hex)
#         msg_bytes = LOGIN_MESSAGE.encode('utf-8')

#         if isinstance(public_key, ed25519.Ed25519PublicKey):
#             public_key.verify(sig_bytes, msg_bytes)
#         else:
#             public_key.verify(sig_bytes, msg_bytes, ec.ECDSA(hashes.SHA256()))
#     except Exception:
#         raise HTTPException(status_code=401, detail="Signature invalid! Login failed.")

#     # Jika lolos, buat Token
#     access_token = create_access_token(data={"sub": username})
#     return {"access_token": access_token, "token_type": "bearer"}

# # 3. Endpoint Verify (Opsional, buat testing manual)
# @app.post("/verify")
# async def verify(username: str = Form(...), message: str = Form(...), signature_hex: str = Form(...)):
#     public_key = load_public_key(username)
#     if not public_key: return {"valid": False, "error": "User not found"}
#     try:
#         sig_bytes = bytes.fromhex(signature_hex)
#         msg_bytes = message.encode('utf-8')
#         if isinstance(public_key, ed25519.Ed25519PublicKey):
#             public_key.verify(sig_bytes, msg_bytes)
#         else:
#             public_key.verify(sig_bytes, msg_bytes, ec.ECDSA(hashes.SHA256()))
#         return {"valid": True, "sender": username}
#     except:
#         return {"valid": False}

# # 4. Secure Relay (Butuh Token!) - INI DIMODIFIKASI
# @app.post("/relay")
# async def relay(
#     recipient: str = Form(...), 
#     message: str = Form(...),
#     # sender tidak lagi diinput manual, tapi diambil dari token
#     current_user: str = Depends(get_current_user) 
# ):
#     """
#     Mengirim pesan aman. Sender otomatis terdeteksi dari Token JWT.
#     """
#     # Cek penerima
#     recipient_key = load_public_key(recipient)
#     if not recipient_key:
#         raise HTTPException(status_code=404, detail=f"Recipient '{recipient}' not found.")

#     # Simpan pesan
#     inbox_file = os.path.join(STORAGE_DIR, f"inbox_{recipient}.txt")
#     timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
#     # Log: Sender diambil dari Token (current_user), jadi pasti asli/secure
#     log_entry = f"[{timestamp}] FROM: {current_user} (Verified via JWT) | MSG: {message}\n"
    
#     with open(inbox_file, "a") as f:
#         f.write(log_entry)

#     return {
#         "status": "sent",
#         "sender": current_user,
#         "recipient": recipient,
#         "message": "Pesan terkirim aman via Secure Session."
#     }

# # 5. Upload PDF (Dengan Tanda Tangan Server)
# @app.post("/upload-pdf")
# async def upload_pdf(file: UploadFile = File(...)):
#     if file.content_type != "application/pdf":
#         raise HTTPException(400, "File must be PDF")
    
#     content = await file.read()
#     priv_key = load_server_private_key()
#     signature = priv_key.sign(content, ec.ECDSA(hashes.SHA256()))
    
#     return {
#         "filename": file.filename,
#         "status": "Signed by Server",
#         "server_signature": signature.hex()
#     }
# File utama API: Level Stella (A) - Secure Session & JWT
# FULL VERSION (Fixed for Swagger UI Token Input)

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional
import os
from datetime import datetime, timedelta

# Import Library Kriptografi
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.exceptions import InvalidSignature

# Import Library JWT
from jose import JWTError, jwt

app = FastAPI(title="Security Service", version="1.0.0")

# --- KONFIGURASI JWT ---
SECRET_KEY = "rahasia_dapur_vegapunk_egghead" # Harusnya ditaruh di .env
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# --- SECURITY SCHEME ---
# Kita gunakan HTTPBearer agar Swagger UI menampilkan input box "Paste Token"
security = HTTPBearer()

# Setup Folder Penyimpanan
STORAGE_DIR = "storage"
if not os.path.exists(STORAGE_DIR):
    os.makedirs(STORAGE_DIR)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Helper Function Kripto ---
def load_public_key(username: str):
    filepath = os.path.join(STORAGE_DIR, f"{username}_pub.pem")
    if not os.path.exists(filepath):
        return None
    with open(filepath, "rb") as key_file:
        try:
            return serialization.load_pem_public_key(key_file.read())
        except Exception:
            return None

def load_server_private_key():
    key_path = "punkhazard-keys/priv.pem" 
    with open(key_path, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

# --- Helper Function JWT (Secure Session) ---
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(auth: HTTPAuthorizationCredentials = Depends(security)):
    """
    Fungsi ini dipanggil otomatis oleh FastAPI untuk memvalidasi Token Bearer.
    Mengambil token dari header Authorization: Bearer <token>
    """
    token = auth.credentials
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return username

# --- Endpoints ---

@app.get("/")
async def get_index():
    return {"message": "Welcome to Punk Records API v1.0 (Secure)"}

@app.get("/health")
async def health_check():
    return {
        "status": "Security Service is running",
        "timestamp": datetime.now().isoformat()
    }

# 1. Store Public Key
@app.post("/store")
async def store_pubkey(username: str = Form(...), file: UploadFile = File(...)):
    try:
        key_content = await file.read()
        serialization.load_pem_public_key(key_content) # Validasi
        
        save_path = os.path.join(STORAGE_DIR, f"{username}_pub.pem")
        with open(save_path, "wb") as f:
            f.write(key_content)
            
        return {"success": True, "message": f"Key {username} saved."}
    except Exception as e:
        return {"success": False, "message": str(e)}

# 2. Login (Mendapatkan Token)
@app.post("/login")
async def login(username: str = Form(...), signature_hex: str = Form(...)):
    """
    User login dengan menandatangani pesan khusus 'LOGIN_ACTION'.
    Jika signature valid -> Dapat Token JWT.
    """
    # Pesan yang wajib ditandatangani untuk login
    LOGIN_MESSAGE = "LOGIN_ACTION" 

    public_key = load_public_key(username)
    if not public_key:
        raise HTTPException(status_code=404, detail="User not found.")

    # Verifikasi Signature
    try:
        sig_bytes = bytes.fromhex(signature_hex)
        msg_bytes = LOGIN_MESSAGE.encode('utf-8')

        if isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(sig_bytes, msg_bytes)
        else:
            public_key.verify(sig_bytes, msg_bytes, ec.ECDSA(hashes.SHA256()))
    except Exception:
        raise HTTPException(status_code=401, detail="Signature invalid! Login failed.")

    # Jika lolos, buat Token
    access_token = create_access_token(data={"sub": username})
    return {"access_token": access_token, "token_type": "bearer"}

# 3. Endpoint Verify (Opsional, buat testing manual)
@app.post("/verify")
async def verify(username: str = Form(...), message: str = Form(...), signature_hex: str = Form(...)):
    public_key = load_public_key(username)
    if not public_key: return {"valid": False, "error": "User not found"}
    try:
        sig_bytes = bytes.fromhex(signature_hex)
        msg_bytes = message.encode('utf-8')
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(sig_bytes, msg_bytes)
        else:
            public_key.verify(sig_bytes, msg_bytes, ec.ECDSA(hashes.SHA256()))
        return {"valid": True, "sender": username}
    except:
        return {"valid": False}

# 4. Secure Relay (Butuh Token!)
@app.post("/relay")
async def relay(
    recipient: str = Form(...), 
    message: str = Form(...),
    # sender tidak lagi diinput manual, tapi diambil dari token
    current_user: str = Depends(get_current_user) 
):
    """
    Mengirim pesan aman. Sender otomatis terdeteksi dari Token JWT.
    PASTIKAN SUDAH KLIK 'AUTHORIZE' DI SWAGGER UI.
    """
    # Cek penerima
    recipient_key = load_public_key(recipient)
    if not recipient_key:
        raise HTTPException(status_code=404, detail=f"Recipient '{recipient}' not found.")

    # Simpan pesan
    inbox_file = os.path.join(STORAGE_DIR, f"inbox_{recipient}.txt")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Log: Sender diambil dari Token (current_user), jadi pasti asli/secure
    log_entry = f"[{timestamp}] FROM: {current_user} (Verified via JWT) | MSG: {message}\n"
    
    with open(inbox_file, "a") as f:
        f.write(log_entry)

    return {
        "status": "sent",
        "sender": current_user,
        "recipient": recipient,
        "message": "Pesan terkirim aman via Secure Session."
    }

# 5. Upload PDF (Dengan Tanda Tangan Server)
@app.post("/upload-pdf")
async def upload_pdf(file: UploadFile = File(...)):
    if file.content_type != "application/pdf":
        raise HTTPException(400, "File must be PDF")
    
    content = await file.read()
    priv_key = load_server_private_key()
    signature = priv_key.sign(content, ec.ECDSA(hashes.SHA256()))
    
    return {
        "filename": file.filename,
        "status": "Signed by Server",
        "server_signature": signature.hex()
    }