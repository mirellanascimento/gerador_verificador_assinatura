# Parte II: Assinatura
    # 1. Cálculo de hashes da mensagem em claro (função de hash SHA-3)
    # 2. Assinatura da mensagem (cifração do hash da mensagem)
    # 3. Formatação do resultado (caracteres especiais e informações para verificação em BASE64)

from hashlib import sha3_256
import rsa_oaep
import base64

def sign_message(message, public_key):
    hash3_m = sha3_256(message).digest()
    return rsa_oaep.rsa_encode(int.from_bytes(hash3_m, "big"), public_key)

def verify_signature(message, private_key, assinatura):
    hash_s = sha3_256(message).digest()    
    return rsa_oaep.rsa_decode(int.from_bytes(assinatura, "big"), private_key) == int.from_bytes(hash_s, "big")






