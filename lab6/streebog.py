from __future__ import annotations

import re
from pathlib import Path
from typing import Sequence, Tuple

BLOCK_SIZE = 64
DIGEST_LENGTH = 64
_ROUNDS = 12


def _load_constants() -> Tuple[bytes, bytes, bytes, Tuple[bytes, ...]]:
    base_dir = Path(__file__).resolve().parent.parent / "lab5" / "server" / "src"
    source = base_dir / "streebog_constants.h"
    try:
        text = source.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise RuntimeError(f"Cannot locate Streebog constants at {source}") from exc

    def parse(name: str) -> bytes:
        pattern = re.compile(
            rf"static const uint8_t {name}\[\] = \{{([^}}]+)\}};",
            re.MULTILINE | re.DOTALL,
        )
        match = pattern.search(text)
        if not match:
            raise RuntimeError(f"Failed to locate constant array {name} in {source}")
        values = [int(value, 16) for value in re.findall(r"0x[0-9a-fA-F]+", match.group(1))]
        return bytes(values)

    pi = parse("STREEBOG_PI")
    tau = parse("STREEBOG_TAU")
    l = parse("STREEBOG_L")
    c = parse("STREEBOG_C")

    if len(pi) != 256:
        raise RuntimeError("Unexpected STREEBOG_PI length")
    if len(tau) != BLOCK_SIZE:
        raise RuntimeError("Unexpected STREEBOG_TAU length")
    if len(l) != BLOCK_SIZE * 8:
        raise RuntimeError("Unexpected STREEBOG_L length")
    if len(c) != _ROUNDS * BLOCK_SIZE:
        raise RuntimeError("Unexpected STREEBOG_C length")

    round_constants = tuple(c[i * BLOCK_SIZE : (i + 1) * BLOCK_SIZE] for i in range(_ROUNDS))
    return pi, tau, l, round_constants


_PI, _TAU, _L, _ROUND_CONSTANTS = _load_constants()


def _xor_bytes(a: Sequence[int], b: Sequence[int]) -> bytearray:
    return bytearray((x ^ y) & 0xFF for x, y in zip(a, b))


def _add_bytes(a: Sequence[int], b: Sequence[int]) -> bytearray:
    carry = 0
    result = bytearray(BLOCK_SIZE)
    for i in range(BLOCK_SIZE):
        total = int(a[i]) + int(b[i]) + carry
        result[i] = total & 0xFF
        carry = total >> 8
    return result


def _s_layer(block: Sequence[int]) -> bytearray:
    output = bytearray(BLOCK_SIZE)
    for i in range(BLOCK_SIZE):
        output[i] = _PI[block[BLOCK_SIZE - 1 - i]]
    return output


def _p_layer(block: Sequence[int]) -> bytearray:
    output = bytearray(BLOCK_SIZE)
    for i in range(BLOCK_SIZE):
        output[i] = block[_TAU[BLOCK_SIZE - 1 - i]]
    return output


def _l_layer(block: Sequence[int]) -> bytearray:
    output = bytearray(BLOCK_SIZE)
    for i in range(7, -1, -1):
        for n in range(8):
            p = 63
            acc = 0
            for j in range(7, -1, -1):
                byte = block[i * 8 + j]
                for k in range(8):
                    if (byte >> k) & 0x01:
                        acc ^= _L[p * 8 + n]
                    p -= 1
            output[i * 8 + n] = acc
    return output


def _spl(block: Sequence[int]) -> bytearray:
    return _l_layer(_p_layer(_s_layer(block)))


def _encrypt(key: Sequence[int], block: Sequence[int]) -> bytearray:
    state = _xor_bytes(key, block)
    round_key = bytearray(key)
    for i in range(_ROUNDS):
        state = _spl(state)
        round_key = _xor_bytes(round_key, _ROUND_CONSTANTS[i])
        round_key = _spl(round_key)
        state = _xor_bytes(round_key, state)
    return state


def _g_transform(N: Sequence[int], h: Sequence[int], m: Sequence[int]) -> bytearray:
    K = _spl(_xor_bytes(h, N))
    t = _encrypt(K, m)
    result = _xor_bytes(t, h)
    return _xor_bytes(result, m)


def hash512(data: bytes) -> bytes:
    h = bytearray(BLOCK_SIZE)
    N = bytearray(BLOCK_SIZE)
    Sigma = bytearray(BLOCK_SIZE)
    v512 = bytearray(BLOCK_SIZE)
    v512[1] = 0x02
    zero_block = bytes(BLOCK_SIZE)

    remaining = len(data)
    while remaining >= BLOCK_SIZE:
        offset = remaining - BLOCK_SIZE
        block = bytearray(data[offset : offset + BLOCK_SIZE])
        h = _g_transform(N, h, block)
        N = _add_bytes(N, v512)
        Sigma = _add_bytes(Sigma, block)
        remaining -= BLOCK_SIZE

    block = bytearray(BLOCK_SIZE)
    if remaining > 0:
        block[BLOCK_SIZE - remaining :] = data[:remaining]
    block[-1] = 0x01
    h = _g_transform(N, h, block)

    len_block = bytearray(BLOCK_SIZE)
    bit_len = (remaining * 8) & 0xFFFFFFFF
    len_block[60] = bit_len & 0xFF
    len_block[61] = (bit_len >> 8) & 0xFF
    len_block[62] = (bit_len >> 16) & 0xFF
    len_block[63] = (bit_len >> 24) & 0xFF

    N = _add_bytes(N, len_block)
    Sigma = _add_bytes(Sigma, block)

    h = _g_transform(zero_block, h, N)
    h = _g_transform(zero_block, h, Sigma)
    return bytes(h)


__all__ = ["hash512", "BLOCK_SIZE", "DIGEST_LENGTH"]
