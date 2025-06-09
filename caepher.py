

import random
import pandas as pd
import struct
from typing import List
import base64


_N = 5

_MESSAGE_HEADER_FMT = '>16sL11x'
_MESSAGE_HEADER_SIZE = struct.calcsize(_MESSAGE_HEADER_FMT)

_PRIVATE_HEADER_FMT = '>16sHHHH7x'
_PRIVATE_HEADER_SIZE = struct.calcsize(_PRIVATE_HEADER_FMT)

_PUBLIC_HEADER_FMT = '>16sHH11x'
_PUBLIC_HEADER_SIZE = struct.calcsize(_PUBLIC_HEADER_FMT)

_ENCODING_VERSION = 'CAO-0.1'

df_reversible = pd.read_csv("reversible.csv")


def get_random_reversible_rules(L, n):
    df = df_reversible[df_reversible["L"] == L]
    rules = []

    for i in range(n):
        rules.append(int(df.loc[random.choice(df.index)]['rule']))

    return rules


def bit_at(x, k):
    return (x >> k) & 1


def rotate_right(state, shift_amount, L):
    return ((state >> shift_amount) |
                  ((state & ((1 << shift_amount) - 1)) << (L - shift_amount))) & ((1 << L) - 1)


def int_to_bytes(i : int, n_bits : int):
    return i.to_bytes((n_bits+7) // 8, 'big')


def bytes_to_base64(b: bytes) -> str:
    return base64.b64encode(b).decode('ascii')


def chunk_bytes(data: bytes, size: int) -> List[int]:
    bitstr = ''.join(f'{byte:08b}' for byte in data)

    pad_len = (size - len(bitstr) % size) % size
    bitstr = bitstr + '0' * pad_len

    return [
        int(bitstr[i:i+size], 2)
        for i in range(0, len(bitstr), size)
    ]

def unchunk_bytes(chunks: List[int], size: int) -> bytes:
    bitstr = ''.join(f'{chunk:0{size}b}' for chunk in chunks)

    pad_len = (8 - len(bitstr) % 8) % 8
    bitstr = bitstr

    return bytes(
        int(bitstr[i:i+8], 2)
        for i in range(0, len(bitstr), 8)
    )


def pack_message(byte_length: int, message: bytes) -> bytes:
    ident = _ENCODING_VERSION + ':msg'
    bname = ident.encode('ascii')
    if len(bname) > 16:
        raise ValueError("Encoding identifier too long")
    bname = bname.ljust(16, b'\x00')
    header = struct.pack(_MESSAGE_HEADER_FMT, bname, byte_length)
    return header + message


def unpack_message(data: bytes) -> tuple[int, bytes]:
    if len(data) < _MESSAGE_HEADER_SIZE:
        raise ValueError(f"data too short, need at least {_MESSAGE_HEADER_SIZE} bytes")

    bname, byte_length = struct.unpack(_MESSAGE_HEADER_FMT, data[:_MESSAGE_HEADER_SIZE])
    name = bname.rstrip(b'\x00').decode('ascii')

    if name != _ENCODING_VERSION + ':msg':
        raise ValueError(f"Invalid encoding {name}")

    message_bytes = data[_MESSAGE_HEADER_SIZE:]
    return byte_length, message_bytes


def pack_public_key(ca_length: int, repetitions: int, rule: int) -> bytes:
    ident = _ENCODING_VERSION + ':pub'

    space = 1 << ca_length

    # encode and pad/truncate name
    bname = ident.encode('ascii')
    assert len(bname) <= 16

    bname = bname.ljust(16, b'\x00')

    header = struct.pack(_PUBLIC_HEADER_FMT, bname, ca_length, repetitions)

    return header + int_to_bytes(rule, space)


def unpack_public_key(data: bytes) -> tuple[int, int, int]:
    if len(data) < _PUBLIC_HEADER_SIZE:
        raise ValueError(f"data too short, need at least {_PUBLIC_HEADER_SIZE} bytes")

    bname, ca_length, repetitions = struct.unpack(_PUBLIC_HEADER_FMT, data[:_PUBLIC_HEADER_SIZE])
    name = bname.rstrip(b'\x00').decode('ascii')

    if name != _ENCODING_VERSION + ':pub':
        raise ValueError(f"Invalid encoding {name}")

    rule_bytes = data[_PUBLIC_HEADER_SIZE:]
    rule = int.from_bytes(rule_bytes, byteorder="big")

    return ca_length, repetitions, rule


def pack_private_key(neighborhood_size:int, ca_length: int, repetitions: int, rule_depth: int, rules:List[int]) -> bytes:
    ident = _ENCODING_VERSION + ':prv'

    # encode and pad/truncate name
    bname = ident.encode('ascii')
    assert len(bname) <= 16

    bname = bname.ljust(8, b'\x00')

    header = struct.pack(_PRIVATE_HEADER_FMT, bname, neighborhood_size, ca_length, repetitions, rule_depth)
    rule_bytes = pack_rules(rules, neighborhood_size)

    return header + rule_bytes


def unpack_private_key(data: bytes) -> tuple[int, int, int, int, List[int]]:
    if len(data) < _PRIVATE_HEADER_SIZE:
        raise ValueError(f"data too short, need at least {_PRIVATE_HEADER_SIZE} bytes")

    bname, neighborhood_size, ca_length, repetitions, rule_depth = struct.unpack(_PRIVATE_HEADER_FMT, data[:_PRIVATE_HEADER_SIZE])
    name = bname.rstrip(b'\x00').decode('ascii')

    if name != _ENCODING_VERSION + ':prv':
        raise ValueError(f"Invalid encoding {name}")

    rule_bytes = data[_PRIVATE_HEADER_SIZE:]

    return neighborhood_size, ca_length, repetitions, rule_depth, unpack_rules(rule_bytes, neighborhood_size)


def pack_rules(rules, neighborhood_size):
    return b''.join([
        int_to_bytes(rule, 1 << neighborhood_size)
        for rule in rules
    ])


def unpack_rules(rule_bytes: bytes, neighborhood_size: int) -> List[int]:
    # how many bits each rule was
    space = 1 << neighborhood_size
    # how many bytes we wrote per rule
    chunk_size = (space + 7) // 8

    if len(rule_bytes) % chunk_size != 0:
        raise ValueError(f"Total bytes {len(rule_bytes)} not a multiple of chunk size {chunk_size}")

    rules = []
    for i in range(0, len(rule_bytes), chunk_size):
        chunk = rule_bytes[i: i + chunk_size]
        rule = int.from_bytes(chunk, byteorder="big")
        rules.append(rule)

    return rules


def extract_window(state, i, L, N):
    w = 0
    for j in range(N):
        idx = (i + j) % L
        bit = bit_at(state, idx) & 1
        w = (w << 1) | bit
    return w


def apply_once(state, rule, L) -> bytes:
    out = 0
    for i in range(L):
        rotated = rotate_right(state, i, L)
        bit_i = bit_at(rule, rotated)
        out |= (bit_i << i)
    return out


def apply_rule_on_ring(state, rule, L, N):
    out = 0
    for i in range(L):
        w = extract_window(state, i, L, N)
        bit_i = bit_at(rule, w) & 1
        out |= (bit_i << i)
    return out


def apply_rules(state, rules, L, N):
    y = state
    for rule in rules:
        y = apply_rule_on_ring(y, rule, L, N)
    return y


def make_inverse_map(rules, L, N):
    space = 1 << L
    inverse_map = [0] * space
    used = [False] * space

    for x in range(space):
        y = apply_rules(x, rules, L, N)
        if used[y]:
            raise Exception(f"Already encountered output {y} at x={x}")
        used[y] = True
        inverse_map[y] = x

    return inverse_map


def make_public_key(rules, L, N):
    space = 1 << L
    g_rule = 0
    for x in range(space):
        y = apply_rules(x, rules, L, N)
        if bit_at(y, 0):
            g_rule |= (1 << x)
    return g_rule


def generate_key_pair(neighborhood_size=5, ca_length=15, repetitions=3, rule_depth=10) -> tuple[bytes, bytes]:
    if neighborhood_size != _N:
        raise Exception("Only neighborhood size 5 supported")

    rules = get_random_reversible_rules(ca_length, n=rule_depth)
    private_key = pack_private_key(neighborhood_size, ca_length, repetitions, rule_depth, rules)

    encoding_rule = make_public_key(rules, ca_length, neighborhood_size)
    public_key = pack_public_key(ca_length, repetitions, encoding_rule)

    return private_key, public_key

def encrypt(public_key: bytes, message: bytes) -> bytes:
    ca_length, repetitions, encoding_rule = unpack_public_key(public_key)
    chunks = chunk_bytes(message, ca_length)

    for c in range(len(chunks)):
        for _ in range(repetitions):
            chunks[c] = apply_once(chunks[c], encoding_rule, ca_length)

    return pack_message(
        len(message),
        unchunk_bytes(chunks, ca_length)
    )


def decrypt(private_key: bytes, encoded_bytes: bytes) -> bytes:
    neighborhood_size, ca_length, repetitions, rule_depth, rules = unpack_private_key(private_key)

    if len(rules) != rule_depth:
        raise ValueError(f"Invalid rule set, expected {rule_depth} rules")

    inverse = make_inverse_map(rules, ca_length, neighborhood_size)

    byte_length, encoded_payload = unpack_message(encoded_bytes)
    chunks = chunk_bytes(encoded_payload, ca_length)

    for c in range(len(chunks)):
        for _ in range(repetitions):
            chunks[c] = inverse[chunks[c]]

    recovered = unchunk_bytes(chunks, ca_length)
    return recovered[:byte_length]


def key_string(key: bytes) -> str:
    return bytes_to_base64(key)