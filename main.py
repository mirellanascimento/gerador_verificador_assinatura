from key_generator import get_keys
import rsa_oaep
import signature
import base64


def main():

    print("PARTE 1: Geração de chaves e cifra ------\n")

    with open("input.txt", "rb") as file:
        message = file.read()

    # Gerar as chages
    public_key, private_key = get_keys()

    msg_enc = rsa_oaep.encrypt(message, public_key)
    msg_enc = msg_enc.to_bytes((msg_enc.bit_length() + 7) // 8, 'big')
    print(f'Mensagem cifrada: {msg_enc}')

    with open("output.txt", "wb") as file:
        file.write(msg_enc)

    msg_dec = rsa_oaep.decrypt(int.from_bytes(msg_enc, "big"), private_key)
    print(f'Mensagem decifrada: {msg_dec}')


    print("\nParte II: Assinatura\n")

    assinatura = signature.sign_message(message, public_key)
    assinatura = base64.b64encode(assinatura)
    print(f'Mensangem assinada: {assinatura}\n')

    print("Parte III: Verificação\n")

    assinatura = base64.b64decode(assinatura)
    dec_assinatura = signature.verify_signature(message, private_key, assinatura)

    print()

    if dec_assinatura:
        print("Verificação correnta")
    else:
        print("Verificação incorrenta")

if __name__ == '__main__':
    main()