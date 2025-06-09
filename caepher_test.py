import pytest
import random

from caepher import get_random_reversible_rules
from caepher import apply_rules, make_inverse_map

def test_get_random_reversible_rules():
    L = 15
    N = 5
    rules = get_random_reversible_rules(L, 4)

    space = 1 << L
    x = random.randrange(space)
    y = apply_rules(x, rules, L, N)

    inverse = make_inverse_map(rules, L, N)

    assert x == inverse[y]


from caepher import bit_at, rotate_right, int_to_bytes, chunk_bytes, unchunk_bytes

def test_bit_at():
    assert bit_at(0b1010, 0) == 0
    assert bit_at(0b1010, 1) == 1
    assert bit_at(0b1010, 2) == 0
    assert bit_at(0b1010, 3) == 1


def test_rotate_right():
    assert rotate_right(0b1101, 1, 4) == 0b1110
    assert rotate_right(0b1010, 2, 4) == 0b1010
    assert rotate_right(0b1001, 3, 4) == 0b0011


def test_int_to_bytes():
    assert int_to_bytes(0, 8) == b'\x00'
    assert int_to_bytes(255, 8) == b'\xff'
    assert int_to_bytes(256, 9) == b'\x01\x00'  # 256 needs 2 bytes for 9 bits
    assert int_to_bytes(0xABCD, 16) == b'\xab\xcd'


def test_chunk_bytes_basic():
    data = b'\xff'  # 0b11111111
    chunks = chunk_bytes(data, 4)
    assert chunks == [0b1111, 0b1111]


def test_chunk_bytes_with_padding():
    data = b'\x0f'  # 0b00001111
    chunks = chunk_bytes(data, 5)  # 8 bits padded to 10
    assert chunks == [0b00001, 0b11100]  # Expect padded result


def test_unchunk_bytes_basic():
    chunks = [0b10101010, 0b11110000]
    data = unchunk_bytes(chunks, 8)
    assert data == bytes(chunks)


def test_roundtrip_no_padding():
    original = b'\xab\xcd\xef'
    chunks = chunk_bytes(original, 12)
    recovered = unchunk_bytes(chunks, 12)
    assert recovered.startswith(original)


def test_roundtrip_all_chunk_sizes():
    data = b'\x12\x34\x56\x78\x9A'
    for size in range(1, 16):
        chunks = chunk_bytes(data, size)
        reconstructed = unchunk_bytes(chunks, size)
        assert reconstructed.startswith(data)


def test_chunkempty():
    assert chunk_bytes(b'', 5) == []
    assert unchunk_bytes([], 5) == b''


from caepher import (
    pack_private_key, unpack_private_key,
    pack_public_key, unpack_public_key,
    pack_rules, unpack_rules,
    pack_message, unpack_message
)

@pytest.fixture
def sample_rules():
    return [243, 1, 42, 255]

def test_pack_unpack_rules_roundtrip(sample_rules):
    ns = 5
    packed = pack_rules(sample_rules, ns)
    unpacked = unpack_rules(packed, ns)
    assert unpacked == sample_rules

def test_pack_private_key_roundtrip(sample_rules):
    ns, length, reps, depth = 5, 16, 2, 4
    packed = pack_private_key(ns, length, reps, depth, sample_rules)
    out_ns, out_length, out_reps, out_depth, out_rules = unpack_private_key(packed)
    assert (out_ns, out_length, out_reps, out_depth) == (ns, length, reps, depth)
    assert out_rules == sample_rules

def test_unpack_private_key_too_short():
    with pytest.raises(ValueError):
        unpack_private_key(b'\x00' * 5)

def test_unpack_private_key_bad_version(sample_rules):
    # corrupt header version
    ns, length, reps, depth = 5,1,1,4
    packed = pack_private_key(ns, length, reps, depth, sample_rules)
    bad = bytearray(packed)
    bad[0:2] = b'XX'  # break the ASCII version tag
    with pytest.raises(ValueError):
        unpack_private_key(bytes(bad))

def test_pack_public_key_roundtrip(sample_rules):
    length, reps, rule = 5, 16, 22222
    packed = pack_public_key(length, reps, rule)
    out_length, out_reps, out_rule = unpack_public_key(packed)
    assert (out_length, out_reps, out_rule) == (length, reps, rule)

def test_unpack_public_key_too_short():
    with pytest.raises(ValueError):
        unpack_public_key(b'\x00' * 5)

def test_unpack_public_key_bad_version(sample_rules):
    # corrupt header version
    length, reps, rule = 5, 16, 22222
    packed = pack_public_key(length, reps, rule)
    bad = bytearray(packed)
    bad[0:2] = b'XX'  # break the ASCII version tag
    with pytest.raises(ValueError):
        unpack_public_key(bytes(bad))

def test_pack_unpack_message():
    message = bytes('secret message', encoding="utf-8")
    packed = pack_message(len(message), message)
    byte_length, unpacked = unpack_message(packed)
    assert byte_length == len(message)
    assert unpacked == message


from caepher import (
    extract_window,
    apply_once,
    apply_rule_on_ring,
    make_public_key,
)


def test_extract_window():
    state = 0b110101
    assert extract_window(state, 2, 6, 3) == 0b101
    assert extract_window(state, 4, 6, 2) == 0b11
    assert extract_window(state, 0, 6, 4) == 0b1010

def test_apply_once():
    state = 0b1101
    rule = 0xFFFF  # Rule that maps everything to 1
    L = 4
    assert apply_once(state, rule, L) == 0b1111

    rule = 0b0000  # Rule that maps everything to 0
    assert apply_once(state, rule, L) == 0b0000

def test_apply_rule_on_ring():
    state = 0b1101
    rule = 0xFFFF  # Rule that maps everything to 1
    L = 4
    N = 2
    assert apply_rule_on_ring(state, rule, L, N) == 0b1111

    rule = 0b0000  # Rule that maps everything to 0
    assert apply_rule_on_ring(state, rule, L, N) == 0b0000

def test_apply_rules():
    state = 0b1101
    rules = [0xFFFF, 0b0000]  # First, map everything to 1, then to 0
    L = 4
    N = 2
    assert apply_rules(state, rules, L, N) == 0b0000

def test_make_inverse_map():
    rules = [65535]  # Identity mapping
    L = 7
    N = 5
    inverse_map = make_inverse_map(rules, L, N)

    # Verify that the inverse map correctly inverts the rules
    for x in range(1 << L):
        y = apply_rules(x, rules, L, N)
        assert inverse_map[y] == x

def test_make_public_key():
    rules = [0xAAAA, 0x5555]  # Patterns of alternation
    L = 4
    N = 2
    g_rule = make_public_key(rules, L, N)

    # Check that the public key is a valid integer with expected bits
    assert isinstance(g_rule, int)
    assert g_rule.bit_length() >= 0


from caepher import encrypt, decrypt, generate_key_pair

def test_encrypt_fails_with_private():
    message = bytes(0b1011_0111)
    private_key, public_key = generate_key_pair()

    with pytest.raises(ValueError):
        encrypt(private_key, message)

def test_descrypt_fails_with_public():
    message = bytes(0b1011_0111)
    private_key, public_key = generate_key_pair()

    with pytest.raises(ValueError):
        decrypt(public_key, message)

def test_encrypt_decrypt():
    message = bytes("secret message", encoding="utf-8")
    private_key, public_key = generate_key_pair(rule_depth=3)
    encrypted = encrypt(public_key, message)
    decrypted = decrypt(private_key, encrypted)

    assert decrypted == message