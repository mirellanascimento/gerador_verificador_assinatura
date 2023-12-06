import oaep
import key_generator


def rsa_encode(message, public_key):
    e, n = public_key
    return pow(message, e, n)

def rsa_decode(message, private_key):
    d, n = private_key
    return pow(message, d, n)

def encrypt(message, public_key):
    k = public_key[1].bit_length() // 8 
    return rsa_encode(int.from_bytes(oaep.oaep_encode(message, k), byteorder='big'), public_key)

def decrypt(msg_enc, private_key):
    k = private_key[1].bit_length() // 8
    return oaep.oaep_decode(rsa_decode(msg_enc, private_key).to_bytes(k, byteorder='big'), k)