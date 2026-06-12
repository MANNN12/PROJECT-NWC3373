import struct
import os

# s-box for nibble substitution (4-bit in, 4-bit out)
# picked values manually to avoid fixed points and simple patterns
SBOX = [
    0x6, 0x4, 0xC, 0x5, 0x0, 0x7, 0x2, 0xE,
    0x1, 0xF, 0x3, 0xD, 0x8, 0xA, 0x9, 0xB,
]

NUM_ROUNDS = 8

# using golden ratio fractional bits as a mixing constant
# same idea as in TEA cipher
DELTA = 0x9E3779B9


def apply_sbox(val):
    # go through each nibble of the 32-bit word and substitute it
    out = 0
    for i in range(8):
        n = (val >> (i * 4)) & 0xF
        out |= SBOX[n] << (i * 4)
    return out


def rotate_left(val, n, bits=32):
    n = n % bits
    mask = (1 << bits) - 1
    return ((val << n) | (val >> (bits - n))) & mask


def rotate_right(val, n, bits=32):
    n = n % bits
    mask = (1 << bits) - 1
    return ((val >> n) | (val << (bits - n))) & mask


def F(R, subkey):
    # round function - mix R with subkey then diffuse
    x = (R ^ subkey) & 0xFFFFFFFF
    x = (x + DELTA) & 0xFFFFFFFF   # add constant to break symmetry
    x = apply_sbox(x)               # non-linear substitution
    x = rotate_left(x, 7)           # bit diffusion
    return x


def key_schedule(key_bytes):
    # split 128-bit key into 4 words then derive one subkey per round
    if len(key_bytes) != 16:
        raise ValueError("need exactly 16 bytes for the key")

    words = list(struct.unpack(">4I", key_bytes))
    subkeys = []

    for i in range(NUM_ROUNDS):
        # mix two different key words with round-dependent rotations
        a = rotate_left(words[i % 4], (i * 3) % 32)
        b = rotate_right(words[(i + 1) % 4], (i * 5) % 32)
        subkeys.append((a ^ b) & 0xFFFFFFFF)

    return subkeys


def feistel_encrypt(block, subkeys):
    # standard feistel: split block into two halves, run rounds
    L = (block >> 32) & 0xFFFFFFFF
    R = block & 0xFFFFFFFF

    for k in subkeys:
        f_out = F(R, k)
        L, R = R, L ^ f_out

    # undo the final swap
    return (R << 32) | L


def feistel_decrypt(block, subkeys):
    # same structure, just reverse the subkey order
    return feistel_encrypt(block, list(reversed(subkeys)))


def encrypt(plaintext, key):
    assert len(plaintext) == 8
    assert len(key) == 16

    sk = key_schedule(key)
    pt_int = int.from_bytes(plaintext, "big")
    ct_int = feistel_encrypt(pt_int, sk)
    return ct_int.to_bytes(8, "big")


def decrypt(ciphertext, key):
    assert len(ciphertext) == 8
    assert len(key) == 16

    sk = key_schedule(key)
    ct_int = int.from_bytes(ciphertext, "big")
    pt_int = feistel_decrypt(ct_int, sk)
    return pt_int.to_bytes(8, "big")


def run_tests():
    print("--- Feistel Cipher Tests ---\n")

    key = bytes.fromhex("13579bdf02468acefedcba9876543210")
    pt  = b"HELLO_64"

    ct = encrypt(pt, key)
    recovered = decrypt(ct, key)

    print(f"Test 1 - basic encrypt/decrypt")
    print(f"  plaintext : {pt} ({pt.hex()})")
    print(f"  encrypted : {ct.hex()}")
    print(f"  decrypted : {recovered} ({recovered.hex()})")
    print(f"  result    : {'PASS' if recovered == pt else 'FAIL'}\n")

    # test with all zeros
    key2 = bytes(16)
    pt2  = bytes(8)
    ct2  = encrypt(pt2, key2)
    rt2  = decrypt(ct2, key2)
    print(f"Test 2 - all zero input")
    print(f"  plaintext : {pt2.hex()}")
    print(f"  encrypted : {ct2.hex()}")
    print(f"  decrypted : {rt2.hex()}")
    print(f"  result    : {'PASS' if rt2 == pt2 else 'FAIL'}\n")

    # random key and plaintext
    key3 = os.urandom(16)
    pt3  = os.urandom(8)
    ct3  = encrypt(pt3, key3)
    rt3  = decrypt(ct3, key3)
    print(f"Test 3 - random key + plaintext")
    print(f"  plaintext : {pt3.hex()}")
    print(f"  key       : {key3.hex()}")
    print(f"  encrypted : {ct3.hex()}")
    print(f"  decrypted : {rt3.hex()}")
    print(f"  result    : {'PASS' if rt3 == pt3 else 'FAIL'}\n")

    # avalanche test - flip 1 bit, see how many output bits change
    a = bytes(8)
    b = b'\x00\x00\x00\x00\x00\x00\x00\x01'
    ca = encrypt(a, key2)
    cb = encrypt(b, key2)
    diff = bin(int.from_bytes(ca, "big") ^ int.from_bytes(cb, "big")).count("1")
    print(f"Test 4 - avalanche (1-bit change in input)")
    print(f"  ct(000...0) : {ca.hex()}")
    print(f"  ct(000...1) : {cb.hex()}")
    print(f"  bits changed: {diff}/64 ({diff/64*100:.1f}%)")
    print(f"  result      : {'PASS' if diff >= 24 else 'WEAK'}\n")

    # show subkeys generated for test 1 key
    print("Key schedule (subkeys for test 1 key):")
    for i, sk in enumerate(key_schedule(key)):
        print(f"  K{i} = 0x{sk:08X}")


if __name__ == "__main__":
    run_tests()