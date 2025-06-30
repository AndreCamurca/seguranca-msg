import socket
import os
import requests
from ecdsa import SigningKey, VerifyingKey, NIST384p, BadSignatureError
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Parâmetros DH
p = int('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563', 16)
g = 2

# Carrega chave privada do servidor
with open("chave_privada.pem", "rb") as f:
    chave_privada_servidor = SigningKey.from_pem(f.read())

username_servidor = "servidor"

# Inicia servidor
HOST = '127.0.0.1'
PORT = 9090
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(1)
print(f"[+] Servidor ouvindo em {HOST}:{PORT}...")

conn, addr = server.accept()
print(f"[+] Conexão de {addr}")

# Recebe A, assinatura e username do cliente
data = conn.recv(4096).decode().split("||")
A = int(data[0])
assinatura_cliente = bytes.fromhex(data[1])
username_cliente = data[2]
print(f"[+] Recebido A: {A}")
print(f"[+] Username do cliente: {username_cliente}")

# Baixa chave pública do cliente
url = f"https://raw.githubusercontent.com/{username_cliente}/seguranca-msg/main/chave_publica.pem"
res = requests.get(url)
if res.status_code != 200:
    print("[-] Erro ao buscar chave pública do cliente.")
    conn.close()
    exit()

chave_publica_cliente = VerifyingKey.from_pem(res.content)

# Verifica assinatura do cliente
try:
    chave_publica_cliente.verify(assinatura_cliente, f"{A}{username_cliente}".encode())
    print("[+] Assinatura do cliente verificada com sucesso.")
except BadSignatureError:
    print("[-] Assinatura inválida! Encerrando conexão.")
    conn.close()
    exit()

# Gera par DH do servidor
b = int.from_bytes(os.urandom(32), 'big')
B = pow(g, b, p)

# Assina B + username
assinatura_servidor = chave_privada_servidor.sign(f"{B}{username_servidor}".encode())

# Envia B, assinatura e username
msg_envio = f"{B}||{assinatura_servidor.hex()}||{username_servidor}"
conn.send(msg_envio.encode())

# Calcula chave DH compartilhada
S = pow(A, b, p)
print(f"[+] Chave DH compartilhada (S): {S}")

# Recebe pacote final (salt + hmac + iv + mensagem)
data = conn.recv(2048)
salt = data[:16]
hmac_tag = data[16:48]
iv = data[48:64]
mensagem_encriptada = data[64:]

# Deriva chaves
S_bytes = str(S).encode()
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=64,
    salt=salt,
    iterations=100_000,
    backend=default_backend()
)
key_material = kdf.derive(S_bytes)
Key_AES = key_material[:32]
Key_HMAC = key_material[32:]

# Verifica HMAC
h = hmac.HMAC(Key_HMAC, hashes.SHA256(), backend=default_backend())
h.update(iv + mensagem_encriptada)
try:
    h.verify(hmac_tag)
    print("[+] HMAC verificado com sucesso.")
except:
    print("[-] HMAC inválido. Mensagem foi alterada.")
    conn.close()
    exit()

# Descriptografa
cipher = Cipher(algorithms.AES(Key_AES), modes.CBC(iv), backend=default_backend())
decryptor = cipher.decryptor()
mensagem_padded = decryptor.update(mensagem_encriptada) + decryptor.finalize()

# Remove padding
pad = mensagem_padded[-1]
mensagem_clara = mensagem_padded[:-pad]
print(f"[+] Mensagem recebida: {mensagem_clara.decode()}")
