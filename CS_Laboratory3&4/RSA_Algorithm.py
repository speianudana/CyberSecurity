from base64 import b64encode, b64decode
from math import gcd
from random import randrange
from collections import namedtuple
from math import log
from binascii import hexlify, unhexlify


def is_prime(n, k=30):
    if n <= 3:
        return n == 2 or n == 3
    neg_one = n - 1

    # write n-1 as 2^s*d where d is odd
    s, d = 0, neg_one
    while not d & 1:
        s, d = s + 1, d >> 1
    assert 2 ** s * d == neg_one and d & 1

    for i in range(k):
        a = randrange(2, neg_one)
        x = pow(a, d, n)
        if x in (1, neg_one):
            continue
        for r in range(1, s):
            x = x ** 2 % n
            if x == 1:
                return False
            if x == neg_one:
                break
        else:
            return False
    return True


def randprime(N=10 ** 8):
    p = 1
    while not is_prime(p):
        p = randrange(N)
    return p


def multinv(modulus, value):

    x, lastx = 0, 1
    a, b = modulus, value
    while b:
        a, q, b = b, a // b, a % b
        x, lastx = lastx - q * x, x
    result = (1 - lastx * modulus) // value
    if result < 0:
        result += modulus
    assert 0 <= result < modulus and value * result % modulus == 1
    return result


KeyPair = namedtuple('KeyPair', 'public private')
Key = namedtuple('Key', 'exponent modulus')


def keygen( N, public=None):

    prime1 = randprime(N)
    prime2 = randprime(N)
    composite = prime1 * prime2
    totient = (prime1 - 1) * (prime2 - 1)
    if public is None:
        while True:
            private = randrange(totient)
            if gcd(private, totient) == 1:
                break
        public = multinv(totient, private)
    else:
        private = multinv(totient, public)
    assert public * private % totient == gcd(public, totient) == gcd(private, totient) == 1
    assert pow(pow(1234567, public, composite), private, composite) == 1234567
    return KeyPair(Key(public, composite), Key(private, composite))


def encode(msg, pubkey, verbose=False):
    chunksize = int(log(pubkey.modulus, 256))
    outchunk = chunksize + 1
    outfmt = '%%0%dx' % (outchunk * 2,)
    print(msg)
    print(type(msg))
    bmsg = msg.encode()
    result = []
    for start in range(0, len(bmsg), chunksize):
        chunk = bmsg[start:start + chunksize]
        chunk += b'\x00' * (chunksize - len(chunk))
        plain = int(hexlify(chunk), 16)
        coded = pow(plain, *pubkey)
        bcoded = unhexlify((outfmt % coded).encode())
        if verbose: print('Encode:', chunksize, chunk, plain, coded, bcoded)
        result.append(bcoded)
    return b''.join(result)


def decode(bcipher, privkey, verbose=False):
    chunksize = int(log(privkey.modulus, 256))
    outchunk = chunksize + 1
    outfmt = '%%0%dx' % (chunksize * 2,)
    result = []
    for start in range(0, len(bcipher), outchunk):
        bcoded = bcipher[start: start + outchunk]
        coded = int(hexlify(bcoded), 16)
        plain = pow(coded, *privkey)
        chunk = unhexlify((outfmt % plain).encode())
        if verbose: print('Decode:', chunksize, chunk, plain, coded, bcoded)
        result.append(chunk)
    return b''.join(result).rstrip(b'\x00').decode()


def key_to_str(key):
    return ':'.join((('%%0%dx' % ((int(log(number, 256)) + 1) * 2)) % number) for number in key)


def str_to_key(key_str):
    return Key(*(int(number, 16) for number in key_str.split(':')))


if __name__ == '__main__':
    import doctest

    print(doctest.testmod())

    pubkey, privkey = keygen(2 ** 64)

    msg = 'the quick brown fox jumped over the lazy dog'
    h = encode(msg, pubkey, 1)
    h__decode = b64encode(h).decode()
    type(h__decode)
    print('encoded:', h__decode)
    print('private key:', key_to_str(privkey))
    print('public key:', key_to_str(pubkey))
    p = decode(b64decode(h__decode), privkey, 1)
    print(p)
