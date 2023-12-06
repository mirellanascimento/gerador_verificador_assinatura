# Parte II: Assinatura
    # 1. Cálculo de hashes da mensagem em claro (função de hash SHA-3)
    # 2. Assinatura da mensagem (cifração do hash da mensagem)
    # 3. Formatação do resultado (caracteres especiais e informações para verificação em BASE64)

from hashlib import sha3_256
import rsa_oaep
import base64

def sign_message(message, private_key):
    hash_m = sha3_256(message).digest()
    sign = rsa_oaep.rsa_encode(int.from_bytes(hash_m, "big"), private_key)
    return base64.b64encode(sign.to_bytes((sign.bit_length()+7)//8, 'big'))

def verify_signature(message, public_key, sign):
    sign_dec = base64.b64decode(sign)
    hash_s = sha3_256(message).digest()    
    return rsa_oaep.rsa_decode(int.from_bytes(sign_dec, "big"), public_key) == int.from_bytes(hash_s, "big")






