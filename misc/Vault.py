import os
import base64
import re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

JIRA_USER_REGEX = r'JIRA_USER\s*=\s*".*"'
JIRA_USER_GRP_REGEX = r'JIRA_USER\s*=\s*"(.*)"'
JIRA_PASSWORD_REGEX = r'JIRA_PASSWORD\s*=\s*".*"'
JIRA_PASSWORD_GRP_REGEX = r'JIRA_PASSWORD\s*=\s*"(.*)"'
# Funktion zur Schlüsselgenerierung
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Funktion zur Verschlüsselung
def encrypt(data, password):
    salt = os.urandom(16)
    key = generate_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()
    return base64.b64encode(salt + iv + encrypted_data).decode()

# Funktion zur Entschlüsselung
def decrypt(encrypted_data, password):
    
    if encrypted_data.startswith("$CRYPT$"):
        encrypted_data = encrypted_data[7:]
    
    encrypted_data = base64.b64decode(encrypted_data.encode())
    salt, iv, encrypted_data = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    key = generate_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        return (decryptor.update(encrypted_data) + decryptor.finalize()).decode()
    except:
        return None

def process_file(filepath, password):
    with open(filepath, 'r') as file:
        lines = file.readlines()

    new_lines = []
    updated = False 
    for line in lines:
        if line.strip().startswith("#"):
            # Kommentarzeilen überspringen
            new_lines.append(line)
            continue

        if re.match(JIRA_USER_REGEX, line):
            username = re.search(JIRA_USER_GRP_REGEX, line).group(1)
            if not is_encrypted(username):
                encrypted_username = encrypt(username, password)
                line = re.sub(JIRA_USER_REGEX, f'JIRA_USER="$CRYPT${encrypted_username}"', line)
                updated = True
        if re.match(JIRA_PASSWORD_REGEX, line):
            password_data = re.search(JIRA_PASSWORD_GRP_REGEX, line).group(1)
            if not is_encrypted(password_data):
                encrypted_password = encrypt(password_data, password)
                line = re.sub(JIRA_PASSWORD_REGEX, f'JIRA_PASSWORD="$CRYPT${encrypted_password}"', line)
                updated = True
        new_lines.append(line)

    with open(filepath, 'w') as file:
        file.writelines(new_lines)

    return updated
def is_encrypted(data=None,file_path=None):

    if file_path:
        lines = None
        with open(file_path, 'r') as file:
            lines = file.readlines()
        for line in lines:
            match = False
            if re.match(JIRA_USER_REGEX, line):
                username = re.search(JIRA_USER_REGEX, line).group(1)

                if is_encrypted(data=username):
                    match = True
                
            if re.match(JIRA_PASSWORD_REGEX, line):
                password_data = re.search(JIRA_PASSWORD_REGEX, line).group(1)
                
                if is_encrypted(password_data) and match:
                    return True
                else:
                    return False
    if data:
        try:
            if data.startswith("$CRYPT$"):
                base64.b64decode(data[7:].encode())
            else:
                return False
            return True
        except Exception:
            return False

    return False
