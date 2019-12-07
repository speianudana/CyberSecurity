from hashlib import sha1
from random import randrange

from primary_check import is_prime


def to_binary(element):
    return str(element).encode()


def invert(x, p):
    return pow(x, p - 2, p)


def powmod(a, b, p):
    return pow(a, b, p)


def generate_p_q(L, N):
    g = N  # g >= 160
    n = (L - 1) // g
    b = (L - 1) % g
    while True:
        # generate q
        while True:
            s = randrange(1, 2 ** g)
            a = sha1(to_binary(s)).hexdigest()
            zz = (s + 1) % (2 ** g)
            z = sha1(to_binary(zz)).hexdigest()
            U = int(a, 16) ^ int(z, 16)
            mask = 2 ** (N - 1) + 1
            q = U | mask
            if is_prime(q, 20):
                break

        i = 0
        j = 2
        while i < 4096:
            V = []
            for k in range(n + 1):
                arg = (s + j + k) % (2 ** g)
                zzv = sha1(to_binary(arg)).hexdigest()
                V.append(int(zzv, 16))
            W = 0
            for qq in range(0, n):
                W += V[qq] * 2 ** (160 * qq)
            W += (V[n] % 2 ** b) * 2 ** (160 * n)
            X = W + 2 ** (L - 1)
            c = X % (2 * q)
            p = X - c + 1  # p = X - (c - 1)
            if p >= 2 ** (L - 1):
                if is_prime(p, 10):
                    return p, q
            i += 1
            j += n + 1


def generate_g(p, q):
    while True:
        h = randrange(2, p - 1)
        exp = (p - 1) // q
        g = powmod(h, exp, p)
        if g > 1:
            break
    return g


def generate_keys(g, p, q):
    x = randrange(2, q)  # x < q
    y = powmod(g, x, p)
    return x, y


def generate_params():
    N = 160
    L = 1024
    p, q = generate_p_q(L, N)
    g = generate_g(p, q)
    return p, q, g


def sign(M, p, q, g, x):
    if not validate_params(p, q, g):
        raise Exception("Invalid params")
    while True:
        k = randrange(2, q)  # k < q
        r = powmod(g, k, p) % q
        m = int(sha1(M).hexdigest(), 16)
        try:
            s = (invert(k, q) * (m + x * r)) % q
            return r, s
        except ZeroDivisionError:
            pass


def verify(M, r, s, p, q, g, y):
    if not validate_params(p, q, g):
        raise Exception("Invalid params")
    if not validate_sign(r, s, q):
        return False
    try:
        w = invert(s, q)
    except ZeroDivisionError:
        return False
    m = int(sha1(M).hexdigest(), 16)
    u1 = (m * w) % q
    u2 = (r * w) % q
    v = (powmod(g, u1, p) * powmod(y, u2, p)) % p % q
    if v == r:
        return True
    return False


def validate_params(p, q, g):
    if is_prime(p, 10) and is_prime(q, 10):
        return True
    if powmod(g, q, p) == 1 and g > 1 and (p - 1) % q:
        return True
    return False


def validate_sign(r, s, q):
    if 0 > r > q:
        return False
    if 0 > s > q:
        return False
    return True


if __name__ == "__main__":

    p, q, g = generate_params()
    x, y = generate_keys(g, p, q)


    text = "Dana laborator"
    M = str.encode(text, "ascii")
    print(M)
    r, s = sign(M, p, q, g, x)
    if verify(M, r, s, p, q, g, y):
        print('All ok')
    print(M, r, s, p, q, g, y, x, sep='\n')
