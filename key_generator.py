import random
import math

def generate_number(n) -> int:
    return random.getrandbits(n)

def miller_rabin(n, k):

    if n in (2, 3):
        return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        s+=1
        d = (n >> s)

    m = (n - 1) >> s

    for _ in range(k):

        a = random.randint(2, n-2)
        b = pow(a, m, n)

        if b in (1, n-1):
            continue
        for _ in range(s):
            b = pow(b, 2, n)
            if b == (n-1):
                break 
        else:
            return False
    return True

def coprime(phi, e):

    return math.gcd(phi, e) == 1

def get_keys():
    "Function that implemts RSA algorithm"

    primos = []

    while len(primos) < 2:
        p = generate_number(1024)
        if miller_rabin(p, 2) and p not in primos:
            primos.append(p)

    p = primos[0]
    q = primos[1]

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 0
    while True:
        if e < phi and coprime(phi, e):
            break
        e = random.randint(2, phi-1)
    
    d = pow(e, -1, phi)
    public_key = (e,n)
    private_key = (d, n)

    return public_key, private_key

