import time
import os
import json
from feistel_cipher import encrypt, decrypt


def encrypt_file_data(data, key):
    """Encrypt arbitrary-length data using 8-byte blocks with PKCS#7 padding (ECB mode)."""
    pad_len = 8 - (len(data) % 8)
    data = data + bytes([pad_len] * pad_len)
    ciphertext = b""
    for i in range(0, len(data), 8):
        block = data[i:i+8]
        ciphertext += encrypt(block, key)
    return ciphertext


def decrypt_file_data(data, key):
    """Decrypt arbitrary-length data and remove PKCS#7 padding."""
    plaintext = b""
    for i in range(0, len(data), 8):
        block = data[i:i+8]
        plaintext += decrypt(block, key)
    pad_len = plaintext[-1]
    return plaintext[:-pad_len]


def generate_test_file(size_bytes):
    return os.urandom(size_bytes)


def run_performance_test(label, data, key, iterations=3):
    size_kb = len(data) / 1024

    # Encryption timing
    enc_times = []
    for _ in range(iterations):
        start = time.perf_counter()
        ct = encrypt_file_data(data, key)
        end = time.perf_counter()
        enc_times.append(end - start)

    avg_enc = sum(enc_times) / len(enc_times)

    # Decryption timing
    dec_times = []
    for _ in range(iterations):
        start = time.perf_counter()
        rt = decrypt_file_data(ct, key)
        end = time.perf_counter()
        dec_times.append(end - start)

    avg_dec = sum(dec_times) / len(dec_times)

    correct = (rt == data)
    enc_throughput = size_kb / avg_enc   # KB/s
    dec_throughput = size_kb / avg_dec   # KB/s

    return {
        "label":               label,
        "size_bytes":          len(data),
        "size_kb":             round(size_kb, 3),
        "enc_time_ms":         round(avg_enc * 1000, 3),
        "dec_time_ms":         round(avg_dec * 1000, 3),
        "enc_throughput_kbs":  round(enc_throughput, 2),
        "dec_throughput_kbs":  round(dec_throughput, 2),
        "correct":             correct,
        "iterations":          iterations,
    }


def print_table(results):
    print(f"\n{'File Size':<12} {'Enc Time':>12} {'Dec Time':>12} "
          f"{'Enc KB/s':>12} {'Dec KB/s':>12} {'Correct':>8}")
    print("-" * 70)
    for r in results:
        print(f"{r['label']:<12} {r['enc_time_ms']:>10.1f}ms {r['dec_time_ms']:>10.1f}ms "
              f"{r['enc_throughput_kbs']:>10.1f}   {r['dec_throughput_kbs']:>10.1f}   "
              f"{'PASS' if r['correct'] else 'FAIL':>8}")


if __name__ == "__main__":
    key = bytes.fromhex("13579bdf02468acefedcba9876543210")

    sizes = [
        ("1 KB",   1 * 1024),
        ("100 KB", 100 * 1024),
        ("1 MB",   1024 * 1024),
    ]

    results = []
    for label, size in sizes:
        print(f"Testing {label}...", flush=True)
        data = generate_test_file(size)
        r = run_performance_test(label, data, key)
        results.append(r)

    print_table(results)

    with open("perf_results.json", "w") as f:
        json.dump(results, f, indent=2)

    print("\nResults saved to perf_results.json")