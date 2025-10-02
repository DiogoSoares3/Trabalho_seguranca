import os
import json
import base64
import requests
import getpass
import qrcode
import pyotp
import hmac
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidKey

SERVER_URL = "http://127.0.0.1:5001"


def derive_hmac_key_from_password(password: str, username: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=username.encode('utf-8'),
        iterations=240000
    )
    return kdf.derive(password.encode())

def create_username_hmac(username: str, key: bytes) -> str:
    return hmac.new(key, username.encode('utf-8'), hashlib.sha256).hexdigest()

def derive_auth_token(password: str, salt_string: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt_string.encode('utf-8'),
        iterations=480000
    )
    return kdf.derive(password.encode())

def get_user_keys(password: str, file_salt: bytes) -> dict:
    master_key = PBKDF2HMAC(
        algorithm=hashes.SHA256(), 
        length=32, 
        salt=file_salt, 
        iterations=480000
    ).derive(password.encode())
    
    hkdf_content = HKDF(
        algorithm=hashes.SHA256(), 
        length=32, 
        salt=None, 
        info=b'file-content-encryption-key'
    )
    content_key = hkdf_content.derive(master_key)
    
    hkdf_filename = HKDF(
        algorithm=hashes.SHA256(), 
        length=32, 
        salt=None, 
        info=b'filename-hmac-key'
    )
    filename_key = hkdf_filename.derive(master_key)
    
    return {"content_key": content_key, "filename_key": filename_key}


def register():
    username = input("Digite o nome de usuário para cadastro: ")
    password = getpass.getpass("Digite a senha para cadastro: ")

    hmac_key = derive_hmac_key_from_password(password, username)
    
    username_hmac = create_username_hmac(username, hmac_key)

    auth_token = derive_auth_token(password, username_hmac)
    
    response = requests.post(
        f"{SERVER_URL}/register",
        json={
            "username": username_hmac,
            "auth_token": base64.b64encode(auth_token).decode('utf-8')
        }
    )
    
    if response.status_code == 200:
        data = response.json()
        print(data['message'])
        
        totp_secret = data['totp_secret']
        uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="NuvemSimulada")
        qr = qrcode.QRCode()
        qr.add_data(uri)
        qr.print_ascii()
        print("\nEscaneie o QR Code acima com seu app de autenticação (Google Authenticator, etc.)")
        print("Cadastro concluído. Agora você pode fazer login.")
    else:
        print(f"Erro no cadastro: {response.json().get('error')}")

def login():
    username = input("Usuário: ")
    password = getpass.getpass("Senha: ")

    hmac_key = derive_hmac_key_from_password(password, username)
    username_hmac = create_username_hmac(username, hmac_key)
    auth_token = derive_auth_token(password, username_hmac)
    
    response = requests.post(
        f"{SERVER_URL}/login_factor1",
        json={
            "username": username_hmac,
            "auth_token": base64.b64encode(auth_token).decode('utf-8')
        }
    )

    if response.status_code != 200:
        print(f"Falha no Fator 1: {response.json().get('error')}")
        return None, None, None

    print(response.json()['message'])
    
    totp_code = input("Digite o código de 6 dígitos do seu app: ")

    response = requests.post(
        f"{SERVER_URL}/login_factor2",
        json={
            "username": username_hmac,
            "totp_code": totp_code
        }
    )

    if response.status_code == 200:
        data = response.json()
        print(data['message'])
        user_id = data['user_id']
        file_salt = base64.b64decode(data['file_salt'])
        return user_id, password, file_salt
    else:
        print(f"Falha no Fator 2: {response.json().get('error')}")
        return None, None, None

def upload_file(user_id, password, file_salt):
    filepath = input("Digite o caminho do arquivo para enviar: ")
    if not os.path.exists(filepath):
        print("Arquivo não encontrado.")
        return

    keys = get_user_keys(password, file_salt)
    filename = os.path.basename(filepath)
    file_id = hmac.new(keys['filename_key'], filename.encode('utf-8'), hashlib.sha256).hexdigest()

    with open(filepath, "rb") as f:
        content_plaintext = f.read()
    
    nonce_content = os.urandom(12)
    chacha = ChaCha20Poly1305(keys['content_key'])
    content_ciphertext = chacha.encrypt(nonce_content, content_plaintext, None)
    encrypted_file_content = base64.b64encode(nonce_content + content_ciphertext).decode('utf-8')

    response = requests.post(f"{SERVER_URL}/upload", json={"user_id": user_id, "file_id": file_id, "file_data": encrypted_file_content})
    print(response.json()['message'])

def download_file(user_id, password, file_salt):
    filename = input("Digite o nome do arquivo para baixar: ")
    
    keys = get_user_keys(password, file_salt)
    file_id = hmac.new(keys['filename_key'], filename.encode('utf-8'), hashlib.sha256).hexdigest()

    response = requests.post(f"{SERVER_URL}/download", json={"user_id": user_id, "file_id": file_id})
    
    if response.status_code != 200:
        print(f"Erro: {response.json().get('error')}")
        return

    encrypted_payload = base64.b64decode(response.json()['file_data'])
    nonce = encrypted_payload[:12]
    ciphertext = encrypted_payload[12:]
    chacha = ChaCha20Poly1305(keys['content_key'])
    try:
        decrypted_data = chacha.decrypt(nonce, ciphertext, None)
        print("\n--- CONTEÚDO DECIFRADO ---")
        print(decrypted_data.decode('utf-8', errors='ignore'))
        print("--------------------------\n")
    except InvalidKey:
        print("Erro: Falha na decifragem. A tag de autenticação é inválida.")

def main():
    session_user_id = None
    session_password = None
    session_file_salt = None

    while True:
        if not session_user_id:
            print("\n1. Cadastrar novo usuário")
            print("2. Fazer Login")
            print("3. Sair")
            choice = input("> ")
            if choice == '1':
                register()
            elif choice == '2':
                session_user_id, session_password, session_file_salt = login()
            elif choice == '3':
                break
        else:
            print(f"\nLogado com ID de sessão: {session_user_id}")
            print("1. Enviar arquivo")
            print("2. Baixar arquivo")
            print("3. Logout")
            choice = input("> ")
            if choice == '1':
                upload_file(session_user_id, session_password, session_file_salt)
            elif choice == '2':
                download_file(session_user_id, session_password, session_file_salt)
            elif choice == '3':
                session_user_id = None
                session_password = None
                session_file_salt = None
                print("Logout realizado.")

if __name__ == '__main__':
    main()