import hashlib
import json
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple

from streebog import hash512 as streebog_hash512


class GOST3410Error(Exception):
    """Domain specific errors for the GOST 34.10 toolkit."""


@dataclass(frozen=True)
class GOST3410Parameters:
    p: int
    q: int
    a: int


def read_binary(path: Path) -> bytes:
    return path.read_bytes()


def write_json(path: Path, payload: Dict[str, str]) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False))


def read_json(path: Path) -> Dict[str, str]:
    return json.loads(path.read_text())


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)


def modinv(a: int, modulus: int) -> int:
    g, x, _ = egcd(a % modulus, modulus)
    if g != 1:
        raise GOST3410Error("Inverse does not exist")
    return x % modulus


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    small_primes = [
        2,
        3,
        5,
        7,
        11,
        13,
        17,
        19,
        23,
        29,
        31,
        37,
        41,
        43,
        47,
    ]
    for p in small_primes:
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bit_length: int) -> int:
    while True:
        candidate = secrets.randbits(bit_length)
        candidate |= 1
        candidate |= 1 << (bit_length - 1)
        if is_probable_prime(candidate):
            return candidate


def generate_domain_parameters(bits_q: int = 256, bits_p: int = 512) -> GOST3410Parameters:
    if bits_p <= bits_q:
        raise ValueError("bits_p must be greater than bits_q")
    while True:
        q = generate_prime(bits_q)
       
        min_k = max(2, (1 << (bits_p - 1)) // q)
        max_k = (1 << bits_p) // q
        if min_k >= max_k:
            continue
        attempts = 0
        while attempts < 1 << 16:
            k = secrets.randbelow(max_k - min_k) + min_k
            p = q * k + 1
            if p.bit_length() != bits_p:
                attempts += 1
                continue
            if is_probable_prime(p):
               
                while True:
                    g = secrets.randbelow(p - 3) + 2
                    a = pow(g, (p - 1) // q, p)
                    if a != 1:
                        return GOST3410Parameters(p=p, q=q, a=a)
       


def int_to_hex(value: int) -> str:
    return hex(value)[2:]


def hex_to_int(value: str) -> int:
    value = value.strip().lower()
    if value.startswith("0x"):
        value = value[2:]
    return int(value, 16)


def hash_message(data: bytes, hash_name: str) -> int:
    normalized = hash_name.lower()
    if normalized in {
        "streebog",
        "streebog512",
        "streebog-512",
        "gost-streebog-512",
        "gost3411-2012-512",
    }:
        digest = streebog_hash512(data)
    else:
        try:
            digest = hashlib.new(hash_name, data).digest()
        except ValueError as exc:
            raise GOST3410Error(f"Unsupported hash: {hash_name}") from exc
    return int.from_bytes(digest, byteorder="big")


class GOST3410:
    def __init__(self, params: GOST3410Parameters):
        self.params = params

    def sign(self, message: bytes, private_key: int, hash_name: str) -> Tuple[int, int]:
        q = self.params.q
        e = hash_message(message, hash_name) % q
        if e == 0:
            e = 1
        while True:
            k = secrets.randbelow(q - 1) + 1
            r = pow(self.params.a, k, self.params.p) % q
            if r == 0:
                continue
            s = (r * private_key + k * e) % q
            if s == 0:
                continue
            return r, s

    def verify(self, message: bytes, signature: Tuple[int, int], public_key: int, hash_name: str) -> bool:
        r, s = signature
        if not (0 < r < self.params.q and 0 < s < self.params.q):
            return False
        e = hash_message(message, hash_name) % self.params.q
        if e == 0:
            e = 1
        v = modinv(e, self.params.q)
        z1 = (s * v) % self.params.q
        z2 = (-r * v) % self.params.q
        u = pow(self.params.a, z1, self.params.p)
        u = (u * pow(public_key, z2, self.params.p)) % self.params.p
        return (u % self.params.q) == r

def demo() -> None:
    params = generate_domain_parameters()
    private_key = secrets.randbelow(params.q - 1) + 1
    public_key = pow(params.a, private_key, params.p)
    message_text = "Good data to sign and verify"
    message = message_text.encode("utf-8")
    hash_name = "streebog"
    gost = GOST3410(params)
    r, s = gost.sign(message, private_key, hash_name)
    print(f"Message: {message_text}")
    print(f"Public key: {int_to_hex(public_key)}")
    print(f"Signature r: {int_to_hex(r)}")
    print(f"Signature s: {int_to_hex(s)}")
    is_valid = gost.verify(message, (r, s), public_key, hash_name)
    print("Signature verification: {}".format("success" if is_valid else "failure"))

    tampered_message = b"hackers data to hack verification"
    tampered_valid = gost.verify(tampered_message, (r, s), public_key, hash_name)
    print(
        "Tampered verification: {}".format("success" if tampered_valid else "failure")
    )


def main() -> None:
    demo()


if __name__ == "__main__":
    main()
