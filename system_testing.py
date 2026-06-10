import time
import os

class LFSRStreamCipher:
    def __init__(self, key_string: str, num_bits: int = 16):
        """
        A1. Key Generation
        Converts the user's secret password (key string) into an 
        initial state (Seed) for the internal LFSR shift register.
        """
        self.num_bits = num_bits
        
        # Using built-in hash function to convert the string into a unique integer.
        # Modulo masking ensures the state value fits the register size (e.g., 16 bits).
        hashed_key = abs(hash(key_string))
        self.initial_state = hashed_key % (2 ** num_bits - 1)
        
        # LFSR Property: The state cannot start at 0 (All-zero bits will stall the LFSR).
        if self.initial_state == 0:
            self.initial_state = 0b1010101010101011 # Fallback default seed value
            
        # Tap positions for the feedback polynomial (Example: x^16 + x^14 + x^13 + x^11 + 1)
        self.taps = [16, 14, 13, 11]

    def _generate_next_bit(self, state: int) -> tuple[int, int]:
        """
        A1. Keystream Generation (Internal Bit Shift)
        Computes the linear feedback using XOR operations on specific tap positions,
        performs a right bit-shift, and outputs 1 pseudo-random bit.
        """
        feedback_bit = 0
        for tap in self.taps:
            # Extract the bit value at the specific tap position
            bit_at_tap = (state >> (tap - 1)) & 1
            feedback_bit ^= bit_at_tap # Perform XOR operation
            
        output_bit = state & 1 # Extract the rightmost bit as the output stream
        
        # Shift the state to the right and insert the feedback_bit at the Most Significant Bit (MSB)
        new_state = (state >> 1) | (feedback_bit << (self.num_bits - 1))
        return output_bit, new_state

    def _generate_keystream_bytes(self, length_in_bytes: int) -> bytes:
        """
        Aggregates sequential random bits from the LFSR function to construct 
        keystream bytes that precisely match the target file size.
        """
        state = self.initial_state
        keystream = bytearray()
        
        for _ in range(length_in_bytes):
            current_byte = 0
            # Accumulate 8 bits to form 1 byte of data
            for bit_position in range(8):
                output_bit, state = self._generate_next_bit(state)
                current_byte |= (output_bit << bit_position)
            keystream.append(current_byte)
            
        return bytes(keystream)

    def process_file(self, input_file_path: str, output_file_path: str):
        """
        A1. XOR Encryption & Decryption Mechanism
        Reads the target file, generates the corresponding keystream, applies a bitwise 
        XOR operation, and exports either the encrypted ciphertext or recovered plaintext file.
        """
        if not os.path.exists(input_file_path):
            print(f"[Error] File not found: {input_file_path}")
            return
            
        # Read the entire raw byte content from the input file
        with open(input_file_path, 'rb') as f:
            plaintext_bytes = f.read()
            
        file_size = len(plaintext_bytes)
        
        # High-precision start timer (Required for PART B: Performance Testing)
        start_time = time.perf_counter_ns()
        
        # Generate a keystream identical in size to the file length
        keystream_bytes = self._generate_keystream_bytes(file_size)
        
        # Execute bitwise XOR between the file data and the generated keystream
        processed_bytes = bytearray(
            p_byte ^ k_byte for p_byte, k_byte in zip(plaintext_bytes, keystream_bytes)
        )
        
        # High-precision end timer
        end_time = time.perf_counter_ns()
        
        # Write the processed stream into the output destination file
        with open(output_file_path, 'wb') as f:
            f.write(processed_bytes)
            
        # Calculate execution duration converted to milliseconds (ms)
        execution_time_ms = (end_time - start_time) / 1_000_000
        print(f"Success! File processed: {input_file_path} -> {output_file_path}")
        print(f"File Size: {file_size} Bytes | Time Elapsed: {execution_time_ms:.4f} ms\n")
        return execution_time_ms


# =========================================================================
# SYSTEM TESTING HARNESS FOR PERFORMANCE ANALYSIS (100% CORRECT & FIXED)
# =========================================================================
if __name__ == "__main__":
    print("=== NWC3373 PERFORMANCE ANALYSIS BENCHMARK SYSTEM ===\n")
    
    # 1. Inisialisasi Cipher dengan Kunci Rahsia
    secret_key = "OurGroupSecretPassword"
    cipher = LFSRStreamCipher(key_string=secret_key)
    
    # Menetapkan nilai bait (Bytes) yang TEPAT mengikut kehendak soalan
    test_cases = [
        ("sample_1kb.txt", 1024, "encrypted_1kb.bin", "decrypted_1kb.txt"),          # Tepat 1 KB
        ("sample_100kb.txt", 100 * 1024, "encrypted_100kb.bin", "decrypted_100kb.txt"), # Tepat 100 KB
        ("sample_1mb.txt", 1024 * 1024, "encrypted_1mb.bin", "decrypted_1mb.txt")       # Tepat 1 MB
    ]
    
    print("-" * 70)
    print(f"{'File Name':<20} | {'File Size':<12} | {'Encryption (ms)':<17} | {'Decryption (ms)':<17}")
    print("-" * 70)
    
    for input_file, exact_size, enc_file, dec_file in test_cases:
        # Peringkat A: Jana fail data rawak TEPAT mengikut saiz bait yang ditetapkan
        # Tukar ke "wb" (write binary) sebab os.urandom menghasilkan data dalam bentuk bytes
        with open(input_file, "wb") as f:
            f.write(os.urandom(exact_size))
            
        # Peringkat B: Uji Masa Enkripsi
        time_encrypt = cipher.process_file(input_file, enc_file)
        
        # Peringkat C: Uji Masa Dekripsi
        time_decrypt = cipher.process_file(enc_file, dec_file)
        
        # Dapatkan saiz fail sebenar dari OS untuk pengesahan
        actual_size = os.path.getsize(input_file)
        
        # Peringkat D: Cetak baris ringkasan data eksperimen
        print(f"{input_file:<20} | {actual_size:<12} | {time_encrypt:<17.4f} | {time_decrypt:<17.4f}")
        
        # Peringkat E: Pengesahan Integriti (Symmetrical Verification Check)
        with open(input_file, 'rb') as f1, open(dec_file, 'rb') as f2:
            if f1.read() != f2.read():
                print(f"[ERROR]: Data mismatch detected in {input_file} execution pass!")
                
    print("-" * 70)