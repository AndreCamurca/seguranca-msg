import socket
import os
from ecdsa import SigningKey, NIST384p
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Parâmetros DH
p = int('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563', 16)
g = 2

# Carrega chave privada do cliente
with open("chave_privada.pem", "rb") as f:
    chave_privada_cliente = SigningKey.from_pem(f.read())

username_cliente = "AndreCamurca"

# Gera DH: a, A
a = int.from_bytes(os.urandom(32), 'big')
A = pow(g, a, p)

# Assina A + username
mensagem = f"{A}{username_cliente}".encode()
assinatura = chave_privada_cliente.sign(mensagem)

# Envia A, assinatura e username
HOST = '127.0.0.1'
PORT = 9090
cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
cliente.connect((HOST, PORT))
pacote = f"{A}||{assinatura.hex()}||{username_cliente}"
cliente.send(pacote.encode())

# Recebe B, assinatura e username_servidor
resposta = cliente.recv(4096).decode().split("||")
B = int(resposta[0])
assinatura_servidor = bytes.fromhex(resposta[1])
username_servidor = resposta[2]
print(f"[+] Recebido B do servidor: {B}")
print(f"[+] Username do servidor: {username_servidor}")

# Calcula chave DH compartilhada
S = pow(B, a, p)
print(f"[+] Chave DH compartilhada (S): {S}")

# Deriva chaves com PBKDF2
salt = os.urandom(16)
iterations = 100_000
S_bytes = str(S).encode()
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=64,
    salt=salt,
    iterations=iterations,
    backend=default_backend()
)
key_material = kdf.derive(S_bytes)
Key_AES = key_material[:32]
Key_HMAC = key_material[32:]

# Criptografa mensagem
mensagem_clara = b"Mensagem ultra secreta do cliente para o servidor."
iv = os.urandom(16)

cipher = Cipher(algorithms.AES(Key_AES), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()

pad = 16 - len(mensagem_clara) % 16
mensagem_padded = mensagem_clara + bytes([pad] * pad)
mensagem_encriptada = encryptor.update(mensagem_padded) + encryptor.finalize()

# Calcula HMAC
h = hmac.HMAC(Key_HMAC, hashes.SHA256(), backend=default_backend())
h.update(iv + mensagem_encriptada)
hmac_tag = h.finalize()

# Corrompe o pacote para causar erro no servidor
pacote_final = bytearray(salt + hmac_tag + iv + mensagem_encriptada)
pacote_final[-1] ^= 0x01  # Inverte 1 bit no último byte (erro de integridade)
cliente.send(bytes(pacote_final))
print("[!] Mensagem corrompida enviada para causar erro no servidor.")
