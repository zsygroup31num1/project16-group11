from random import randint
import math
import binascii
from sm3 import G_hash


def modinv(a, m):
    x1, x2, x3 = 1, 0, a
    y1, y2, y3 = 0, 1, m
    while y3 != 0:
        q = x3 // y3
        t1, t2, t3 = x1 - q * y1, x2 - q * y2, x3 - q * y3
        x1, x2, x3 = y1, y2, y3
        y1, y2, y3 = t1, t2, t3
    return x1 % m


def addition(x1, y1, x2, y2, a, p):
    if x1 == x2 and y1 == p - y2:
        return False
    if x1 != x2:
        lamda = ((y2 - y1) * modinv(x2 - x1, p)) % p
    else:
        lamda = (((3 * x1 * x1 + a) % p) * modinv(2 * y1, p)) % p
    x3 = (lamda * lamda - x1 - x2) % p
    y3 = (lamda * (x1 - x3) - y1) % p
    return x3, y3


def mutipoint(x, y, k, a, p):
    k = bin(k)[2:]
    qx, qy = x, y
    for i in range(1, len(k)):
        qx, qy = addition(qx, qy, qx, qy, a, p)
        if k[i] == '1':
            qx, qy = addition(qx, qy, x, y, a, p)
    return qx, qy


def kdf(z, klen):
    ct = 1
    k = ''
    for _ in range(math.ceil(klen / 256)):
        k = k + G_hash(hex(int(z + '{:032b}'.format(ct), 2))[2:])
        ct = ct + 1
    k = '0' * ((256 - (len(bin(int(k, 16))[2:]) % 256)) % 256) + bin(int(k, 16))[2:]
    return k[:klen]


# parameters
p = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
a = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
b = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
gx = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
gy = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
n = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
zz = '63E4C6D3B23B0C849CF85841484BFE48F61D59A5B16BA06E6E12D1DA27C5249A'
# 待加密的消息M：encryption standard
# 消息M的16进制表示：656E63 72797074 696F6E20 7374616E 64617264
'''
dB=0x1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0
xB=0x435B39CCA8F3B508C1488AFC67BE491A0F7BA07E581A0E4849A5CF70628A7E0A
yB=0x75DDBA78F15FEECB4C7895E2C1CDF5FE01DEBB2CDBADF45399CCF77BBA076A42
'''
dB = randint(1, n - 1)
xB, yB = mutipoint(gx, gy, dB, a, p)


def decrypt(m: str, d1, d2):
    plen = len(hex(p)[2:])
    m = bin(int(m.encode().hex(), 16))[2:]
    klen = len(m)
    while True:
        k = randint(1, n)
        while k == dB:
            k = randint(1, n)
        x2, y2 = mutipoint(xB, yB, k, a, p)
        x2, y2 = '{:0256b}'.format(x2), '{:0256b}'.format(y2)
        t = kdf(x2 + y2, klen)
        if int(t, 2) != 0:
            break
    x1, y1 = mutipoint(gx, gy, k, a, p)
    x1s, y1s = (plen - len(hex(x1)[2:])) * '0' + \
               hex(x1)[2:], (plen - len(hex(y1)[2:])) * '0' + hex(y1)[2:]
    c1 = '04' + x1s + y1s

    c2 = bin(int(m, 2) ^ int(t, 2))[2:]
    # print('c2',c2)
    c3 = G_hash(hex(int(x2 + m + y2, 2))[2:])

    # t1x, t1y = mutipoint(x1, y1, int(1/d1), a, p)
    # t2x, t2y = mutipoint(x1, y1, int(1/(d1*d2)), a, p)
    # x22, y22 = addition(t1x, t1y, t2x, t2y, a, p)
    # x22, y22 = '{:0256b}'.format(x22), '{:0256b}'.format(y22)
    # t = kdf(x2+y2, klen)
    m2 = bin(int(c2, 2) ^ int(t, 2))[2:]
    u = G_hash(hex(int(x2 + m2 + y2, 2))[2:])
    print('u=', u, 'c3=', c3)
    if (u == c3):
        print('破解成功m2=', m2)
    else:
        print('破解失败')


if __name__ == '__main__':
    d1 = randint(1, n)
    d2 = randint(1, n)
    print(decrypt('hello', d1, d2))