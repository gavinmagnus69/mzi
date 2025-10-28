import hashlib
import secrets
from typing import Optional, Tuple

from streebog import hash512 as streebog_hash512


P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97
A = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94
B = 0xA6
Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893
GX = 0x01
GY = 0x8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14
G_POINT = (GX, GY)

Point = Optional[Tuple[int, int]]


class GOSTError(Exception):
    pass


def modinv(value: int, modulus: int) -> int:
    if value % modulus == 0:
        raise GOSTError("no inverse")
    return pow(value, -1, modulus)


def is_on_curve(point: Point) -> bool:
    if point is None:
        return True
    x, y = point
    return (y * y - (x * x * x + A * x + B)) % P == 0


def point_add(p1: Point, p2: Point) -> Point:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        numerator = (3 * x1 * x1 + A) % P
        denominator = (2 * y1) % P
    else:
        numerator = (y2 - y1) % P
        denominator = (x2 - x1) % P
    slope = (numerator * modinv(denominator, P)) % P
    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mul(k: int, point: Point) -> Point:
    if k % Q == 0 or point is None:
        return None
    if not is_on_curve(point):
        raise GOSTError("point is outside curve")
    result = None
    addend = point
    while k > 0:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def hash_message(message: bytes, hash_name: str = "streebog") -> int:
    name = hash_name.lower()
    if name in {"streebog", "streebog512", "gost3411-2012-512"}:
        digest = streebog_hash512(message)
    else:
        digest = hashlib.new(hash_name, message).digest()
    return int.from_bytes(digest, byteorder="big")


def generate_private_key() -> int:
    return secrets.randbelow(Q - 1) + 1


def derive_public_key(private_key: int) -> Point:
    if not (1 <= private_key < Q):
        raise GOSTError("bad private key")
    return scalar_mul(private_key, G_POINT)


def sign(message: bytes, private_key: int) -> Tuple[int, int]:
    if not (1 <= private_key < Q):
        raise GOSTError("bad private key")
    e = hash_message(message) % Q
    if e == 0:
        e = 1
    while True:
        k = secrets.randbelow(Q - 1) + 1
        c = scalar_mul(k, G_POINT)
        if c is None:
            continue
        r = c[0] % Q
        if r == 0:
            continue
        s = (r * private_key + k * e) % Q
        if s == 0:
            continue
        return r, s


def verify(message: bytes, signature: Tuple[int, int], public_key: Point) -> bool:
    if public_key is None or not is_on_curve(public_key):
        return False
    r, s = signature
    if not (0 < r < Q and 0 < s < Q):
        return False
    e = hash_message(message) % Q
    if e == 0:
        e = 1
    try:
        v = modinv(e, Q)
    except GOSTError:
        return False
    z1 = (s * v) % Q
    z2 = (Q - (r * v % Q)) % Q
    p1 = scalar_mul(z1, G_POINT)
    p2 = scalar_mul(z2, public_key)
    check = point_add(p1, p2)
    if check is None:
        return False
    return check[0] % Q == r


def demo() -> None:
    message = b"Good data to sign and verify"
    private_key = generate_private_key()
    public_key = derive_public_key(private_key)
    r, s = sign(message, private_key)
    print(f"Message: {message.decode()}")
    print(f"Private key: {hex(private_key)[2:]}")
    print(f"Public key X: {hex(public_key[0])[2:]}")
    print(f"Public key Y: {hex(public_key[1])[2:]}")
    print(f"Signature r: {hex(r)[2:]}")
    print(f"Signature s: {hex(s)[2:]}")
    print(f"Signature valid: {verify(message, (r, s), public_key)}")
    print(
        "Tampered valid:",
        verify(b'hackers data to hack verification', (r, s), public_key),
    )


if __name__ == "__main__":
    demo()
