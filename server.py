import os
import json
import base64
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import pyotp
import uvicorn
from dotenv import load_dotenv
load_dotenv("./.env.example")

server_key_hex = os.environ.get('SERVER_KEY')
if not server_key_hex:
    raise ValueError("A variável de ambiente MY_APP_SERVER_KEY não foi definida!")

SERVER_KEY = bytes.fromhex(server_key_hex)


class UserRegister(BaseModel):
    username: str
    auth_token: str

class UserLoginFactor1(BaseModel):
    username: str
    auth_token: str

class UserLoginFactor2(BaseModel):
    username: str
    totp_code: str

class FileUpload(BaseModel):
    user_id: str
    file_id: str
    file_data: str

class FileDownload(BaseModel):
    user_id: str
    file_id: str


app = FastAPI()
DB_FILE = "server_db.json"

def load_db():
    if not os.path.exists(DB_FILE):
        return {}
    with open(DB_FILE, "r") as f:
        return json.load(f)

def save_db(db):
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=4)


@app.post("/register")
def register(user: UserRegister):
    db = load_db()
    
    if user.username in db:
        raise HTTPException(status_code=400, detail="Usuário já existe")

    auth_token_from_client = base64.b64decode(user.auth_token)

    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    verifier = kdf.derive(auth_token_from_client)
    totp_secret = pyotp.random_base32().encode('utf-8')
    file_salt = os.urandom(16)

    key_for_totp = HKDF(
        algorithm=hashes.SHA256(), 
        length=32, 
        salt=None, 
        info=b'key for totp secrets'
    ).derive(SERVER_KEY)
    
    nounce_totp = os.urandom(12)
    
    encrypted_totp = AESGCM(key_for_totp).encrypt(nounce_totp, totp_secret, None)

    db[user.username] = {
        "verifier": base64.b64encode(verifier).decode('utf-8'),
        "salt": base64.b64encode(salt).decode('utf-8'),
        "totp_secret": base64.b64encode(nounce_totp + encrypted_totp).decode('utf-8'),
        "file_salt": base64.b64encode(file_salt).decode('utf-8'),
        "files": {}
    }
    save_db(db)
    
    return {"message": "Usuário registrado com sucesso", "totp_secret": totp_secret.decode('utf-8')}


@app.post("/login_factor1")
def login_factor1(user: UserLoginFactor1):
    db = load_db()
    user_data = db.get(user.username)
    
    if not user_data:
        raise HTTPException(status_code=401, detail="Falha na autenticação do fator 1")

    auth_token_from_client = base64.b64decode(user.auth_token)
    salt = base64.b64decode(user_data['salt'])
    verifier = base64.b64decode(user_data['verifier'])
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    
    try:
        kdf.verify(auth_token_from_client, verifier)
        return {"message": "Fator 1 OK. Prossiga para o fator 2."}
    
    except InvalidKey:
        raise HTTPException(status_code=401, detail="Falha na autenticação do fator 1")


@app.post("/login_factor2")
def login_factor2(user: UserLoginFactor2):
    db = load_db()
    user_data = db.get(user.username)
    if not user_data:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    encrypted_totp = base64.b64decode(user_data['totp_secret'])
    key_for_totp = HKDF(
        algorithm=hashes.SHA256(), 
        length=32, 
        salt=None, 
        info=b'key for totp secrets'
    ).derive(SERVER_KEY)
    
    nonce = encrypted_totp[:12]
    ciphertext = encrypted_totp[12:]
    
    decrypted_totp = AESGCM(key_for_totp).decrypt(nonce, ciphertext, None).decode('utf-8')
    totp = pyotp.TOTP(decrypted_totp)
    
    if totp.verify(user.totp_code):
        return {
            "message": "Autenticação completa com sucesso!",
            "user_id": user.username,
            "file_salt": user_data['file_salt']
        }
    else:
        raise HTTPException(status_code=401, detail="Código TOTP inválido")


@app.post("/upload")
def upload(file: FileUpload):
    db = load_db()
    user_data = db.get(file.user_id)
    if not user_data:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    user_data['files'][file.file_id] = file.file_data
    save_db(db)
    return {"message": f"Arquivo salvo com sucesso."}


@app.post("/download")
def download(file: FileDownload):
    db = load_db()
    user_data = db.get(file.user_id)
    if not user_data or file.file_id not in user_data['files']:
        raise HTTPException(status_code=404, detail="Arquivo não encontrado")

    encrypted_data = user_data['files'][file.file_id]
    return {"file_id": file.file_id, "file_data": encrypted_data}


if __name__ == "__main__":
    uvicorn.run("server:app", host="127.0.0.1", port=5001, reload=True)