#!/usr/bin/env python3
"""
X-Mask Password Encoder v6 - Verified Implementation

Reverse engineered from libSecure.dll (Flexxon X-Mask PRO)
Verified against Logic Analyzer traces (2026-02-04)

ALGORITHM:
1. Initialize buffer: serial (0-7), serial_reversed (248-255), extra bytes (256-257)
2. XOR with PRNG output (128 DWORDs)
3. Bit permutation using scramble_key and password_vector
4. Checksum: sum of 255 byte-swapped 16-bit words, stored BE at 510-511

VERIFIED:
- Password IS used in permutation (bytes 0-N of password_vector)
- Scramble key at dynamic offset: 0xB8 + header[0x3C] + header[0x44]
- Buffer bytes 28, 31 are 0x00 (not 0x20)

UNKNOWN (see v7):
- Extra bytes at password_vector[20,21,25,27] for some operations
- What determines buf[256] value
- Why password_vector[31] != function_code in traces
"""

class TRandomMersenne:
    N, M = 624, 397
    MATRIX_A, UPPER_MASK, LOWER_MASK = 0x9908B0DF, 0x80000000, 0x7FFFFFFF

    def __init__(self, seed: int):
        self.mt = [0] * self.N
        self.mt[0] = seed & 0xFFFFFFFF
        for i in range(1, self.N):
            self.mt[i] = (0x6C078965 * (self.mt[i-1] ^ (self.mt[i-1] >> 30)) + i) & 0xFFFFFFFF
        self.mti = self.N

    def _twist(self):
        mag01 = [0, self.MATRIX_A]
        for i in range(self.N - self.M):
            y = (self.mt[i] & self.UPPER_MASK) | (self.mt[i+1] & self.LOWER_MASK)
            self.mt[i] = self.mt[i + self.M] ^ (y >> 1) ^ mag01[y & 1]
        for i in range(self.N - self.M, self.N - 1):
            y = (self.mt[i] & self.UPPER_MASK) | (self.mt[i+1] & self.LOWER_MASK)
            self.mt[i] = self.mt[i + self.M - self.N] ^ (y >> 1) ^ mag01[y & 1]
        y = (self.mt[self.N-1] & self.UPPER_MASK) | (self.mt[0] & self.LOWER_MASK)
        self.mt[self.N-1] = self.mt[self.M-1] ^ (y >> 1) ^ mag01[y & 1]
        self.mti = 0

    def brandom(self) -> int:
        if self.mti >= self.N:
            self._twist()
        y = self.mt[self.mti]
        self.mti += 1
        y ^= y >> 11
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= y >> 18
        return y & 0xFFFFFFFF

    def irandom(self, min_val: int, max_val: int) -> int:
        raw = self.brandom()
        return int(raw * 2.3283064365386963e-10 * (max_val - min_val + 1)) + min_val


def build_seed(scramble_key: bytes, milliseconds: int) -> int:
    k = scramble_key
    return (k[0] << 24) | (k[2] << 16) | (k[4] << 8) | (milliseconds & 0xFFFF)


def prng_xor(buf: bytearray, seed: int):
    mt = TRandomMersenne(seed)
    for i in range(128):
        rand_val = mt.irandom(0, 0x7FFFFFFE)
        for j in range(4):
            buf[i*4 + j] ^= (rand_val >> (j*8)) & 0xFF


def cbitarray_test(data: bytes, bit_index: int) -> int:
    return (data[bit_index >> 3] >> (bit_index & 7)) & 1


def cbitarray_set(data: bytearray, bit_index: int, value: int):
    byte_idx = bit_index >> 3
    bit_in_byte = bit_index & 7
    if value:
        data[byte_idx] |= (1 << bit_in_byte)
    else:
        data[byte_idx] &= ~(1 << bit_in_byte)


def permute(scramble_key: bytes, password_vector: bytearray, buf: bytearray):
    start_offset = scramble_key[0]
    base_offset = scramble_key[1] & 7
    output_view = memoryview(buf)[start_offset:start_offset+256]
    output_counter = 0
    password_byte = password_vector[0]

    for i in range(64):
        if i != 0 and (output_counter & 7) == 0:
            password_byte = password_vector[i >> 1]
        scramble_bit = cbitarray_test(scramble_key, i)
        for j in range(4):
            bit_position = (output_counter * 8 + j * 8) | base_offset
            password_bit = (password_byte >> 7) & 1
            if scramble_bit == 1:
                output_bit = password_bit
            else:
                output_bit = 1 - password_bit
            cbitarray_set(output_view, bit_position, output_bit)
            password_byte = (password_byte << 1) & 0xFF
        output_counter += 4


def compute_checksum(buf: bytearray):
    """Sum of 255 byte-swapped 16-bit words, stored big-endian at 510-511"""
    checksum = 0
    for i in range(255):
        word = buf[i*2] | (buf[i*2 + 1] << 8)
        word = ((word << 8) | (word >> 8)) & 0xFFFF
        checksum = (checksum + word) & 0xFFFF
    buf[510] = (checksum >> 8) & 0xFF
    buf[511] = checksum & 0xFF


def encode_password(serial: bytes, password: bytes, scramble_key: bytes,
                    milliseconds: int, function_code: int = 0x08) -> bytes:
    """
    Encode password for X-Mask command.

    Note: This is a simplified implementation. The actual DLL behavior
    for password_vector construction is more complex - see XMASK_ENCODER_FINDINGS.md
    """
    # Initialize buffer
    buf = bytearray(512)
    buf[:8] = serial[:8]
    # Bytes 8-247: zeros (default)
    # Bytes 28, 31: remain 0x00 (NOT 0x20 as previously assumed)
    buf[248:256] = serial[::-1]
    buf[256] = 0x00  # TODO: varies by operation (0x00 for auth, 0x02 for temp unlock)
    buf[257] = 0x01

    # Build seed and apply PRNG XOR
    seed = build_seed(scramble_key, milliseconds)
    prng_xor(buf, seed)

    # Build password_vector
    # Verified: password bytes ARE used (not just scramble_key[6] at [14])
    password_vector = bytearray(32)
    password_vector[:len(password)] = password[:32]
    # TODO: Extra bytes at [20,21,25,27] for some operations - origin unknown
    # TODO: password_vector[31] observed as 0x00 in traces, not function_code

    # Apply permutation
    permute(scramble_key, password_vector, buf)

    # Compute and store checksum
    compute_checksum(buf)

    return bytes(buf)


if __name__ == '__main__':
    # Test case: ADDR=10 (temp unlock) from trace - this one has no extra bytes
    print("Test case: ADDR=10 (temp unlock)")
    print("=" * 60)

    EXPECTED_HEX = (
        "7cac7f2254d4e31d6b09d91a60547c6d4d306502f193502e15c6095b1418737f"
        "86139b7e418e40065f0ceb52da7551269b059568ae38d312b6d0c12dd498e949"
        "1d06bc11bfcb0909cb1ec54c46bf141f12ead40b50d01e71bd30b82f526c1003"
        "b3b43d2fa2e5662b469a1f456b5d06776ce49d43628126562541297992e7ce26"
        "4d54be74b7be1a63388769209ff35528c1691e4092e04158b813597469eb5906"
        "9f50d75938a0b83a80aa546f5f9ee95f2e91d2465b3d2503a8618f2d1b050c78"
        "c13c3a2bb4974d4212e1430851bb391b904f8016ca241926197a9222a3970c73"
        "3134a6373e1ac231c011922c82830920fcc0792adcfff81ca92a022e5d50a345"
        "46ec2538757361358f321d6c72f6063564f6de535f78b453d252cc4a8cdf2f6d"
        "e69e433b6ce000146708da7e7d89415c6efead161a0b3930818fc446df563220"
        "1d14f97775d7aa203917280d0d2d05000a38943c9e0dc17d60ed333f9b2b9223"
        "94bd475fdbd10d049312445ecbe6912c222dfb55c6460c2d02018009361bb902"
        "ba0dc74e69dac0516b6f7653c64dc7494e7d665f6e5fb33d0b8e9c2ba9bf2f0f"
        "27090e18bca73230943e21222abe3f05393825152d21b5360692bf3b3eb71a0a"
        "1320822dbe1304338fa3a02d9528b83e29a0f36666598f058b9dd67bccfb8a3d"
        "2b03f160634e6b63e51ea84eb433025c9cc12f2d24d9ca3adb0e2f12150ff661"
    )

    expected = bytes.fromhex(EXPECTED_HEX)
    SERIAL = b'69668301'
    password = b'P4ssw0rd!'
    scramble_key = bytes.fromhex('e656596f75f0ff57')
    ms = 33

    # Manual encode with correct parameters for this test case
    buf = bytearray(512)
    buf[:8] = SERIAL[:8]
    buf[248:256] = SERIAL[::-1]
    buf[256] = 0x02  # Specific to temp unlock
    buf[257] = 0x01

    seed = build_seed(scramble_key, ms)
    prng_xor(buf, seed)

    password_vector = bytearray(32)
    password_vector[:len(password)] = password[:32]
    # No extra bytes for temp unlock

    permute(scramble_key, password_vector, buf)
    compute_checksum(buf)

    matches = sum(1 for a, b in zip(buf, expected) if a == b)
    print(f"Scramble key: {scramble_key.hex()}")
    print(f"Milliseconds: {ms}")
    print(f"Result: {matches}/512 byte matches")

    if matches == 512:
        print("PERFECT MATCH!")
    else:
        diffs = [(i, buf[i], expected[i]) for i in range(512) if buf[i] != expected[i]]
        print(f"Differences ({len(diffs)}):")
        for i, got, exp in diffs[:10]:
            print(f"  Byte {i}: got 0x{got:02X}, expected 0x{exp:02X}")

    # Test case 2: ADDR=6 (authentication) - requires extra bytes
    print("\n" + "=" * 60)
    print("Test case: ADDR=6 (authentication)")
    print("=" * 60)

    EXPECTED_HEX_AUTH = (
        "CCA5724FE07FC93FB85D8D7E1CE9042A99CB753EBB7C000E16A8F9339FF23B07"
        "194962051D99905587D33D513216D43AC627DA5DEED19637BEA9B46CA2F6BA49"
        "771C9A5B3E40C9404CDD7358456722308C1BB61FA5593017AF53E4181E7DA51C"
        "FE450720A3944409B390CF0DDBAFAF4B61C1F5335819D25D0573AA4113A48468"
        "7A9F12766E2DAF14AC62B6054F9EF16392C27409C7378E2A7ADF98254209B72A"
        "6570071EE187761C32EE706BD09D781E8404BF2F55EA644B33C998550494302F"
        "808F5E0202553335C52E3C4EA2D6263F9F62174F3468A205E2C28875F435BD4A"
        "9FDBC53C1CB092005EAC59518C157065BBD72A4C9302322895E89C4576833467"
        "07534D7C2B2EC0228BE2760185C0CA7ABC80642C00AC4359B878265EBD6A684A"
        "738CE07B3098B478B6A8A05CD916B243029B3E4A7BD6D904110C140575807A13"
        "AA7BA6029FD28445CC90A97521CD1F17B2878B0A070A74116071C955E5A83F3F"
        "27170D05157CF73BD6D66C78FDE0DE13EFA65D649478DA137B26DA023FEEA539"
        "1154C558F8E86E663B0A9D04D8093B17F653E45908254C00BDE42E76FF6EB37A"
        "2AAEBC7D8D99CD7C2CDDFF1B422EBE56CE9A4570E859186074C4221E0E0AF56D"
        "346D8C31C58043162F5EAC61E920B47D2878BC21D9F18E6A2A6F2B26AF2F6945"
        "4011E154C8C45C575AFB4E7E5C23510A3B95D3718E839B516CF32F446438D3C7"
    )

    expected_auth = bytes.fromhex(EXPECTED_HEX_AUTH)
    scramble_key_auth = bytes.fromhex('e6c933b3ca9091ce')
    ms_auth = 39

    buf = bytearray(512)
    buf[:8] = SERIAL[:8]
    buf[248:256] = SERIAL[::-1]
    buf[256] = 0x00  # Authentication uses 0x00
    buf[257] = 0x01

    seed = build_seed(scramble_key_auth, ms_auth)
    prng_xor(buf, seed)

    # Authentication requires extra bytes in password_vector
    password_vector = bytearray(32)
    password_vector[:len(password)] = password[:32]
    password_vector[20] = 0x0F
    password_vector[21] = 0x0F
    password_vector[25] = 0x0F
    password_vector[27] = 0xF0

    permute(scramble_key_auth, password_vector, buf)
    compute_checksum(buf)

    matches = sum(1 for a, b in zip(buf, expected_auth) if a == b)
    print(f"Scramble key: {scramble_key_auth.hex()}")
    print(f"Milliseconds: {ms_auth}")
    print(f"Extra bytes: [20]=0x0F, [21]=0x0F, [25]=0x0F, [27]=0xF0")
    print(f"Result: {matches}/512 byte matches")

    if matches == 512:
        print("PERFECT MATCH!")
