from ecdsa import SigningKey, NIST384p

# Gera a chave privada
private_key = SigningKey.generate(curve=NIST384p)

# Salva a chave privada
with open("chave_privada.pem", "wb") as f:
    f.write(private_key.to_pem())

# Salva a chave pública
with open("chave_publica.pem", "wb") as f:
    f.write(private_key.get_verifying_key().to_pem())

print("Chaves geradas e salvas como 'chave_privada.pem' e 'chave_publica.pem'")
