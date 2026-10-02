#!/usr/bin/env python3
"""
X-Mask / X-Mask PRO Protocol Implementation for GreatFET

Implements the LBA-based security protocol for Flexxon X-Mask SD cards.
Both X-Mask and X-Mask PRO use identical wire protocol.

Protocol verified from Saleae logic analyzer traces and libSecure.dll RE.

CRITICAL: Each password operation requires a FRESH header read immediately
before the write, as the scramble key changes on every read.
"""

import struct
import time
from enum import IntEnum
from typing import Optional, Tuple

# LBA Command Mapping
LBA_MODE = 0        # Enter/Leave mode control
LBA_HEADER = 5      # Read security header (CMD17)
LBA_AUTH = 6        # Authentication
LBA_REMOVE_PW = 7   # Remove password
LBA_SET_PW = 8      # Set password (primary)
LBA_SET_PW_ALT = 9  # Set password (alternate/partition)
LBA_TEMP_UNLOCK = 10  # Temporary unlock

SERIAL = b"69668301"  # example card identifier used by the demos/tests below


class CardStatus(IntEnum):
    """Card security status (from header offset 0x1C1)."""
    UNLOCKED = 0x00       # Card is unlocked (no password set)
    LOCKED = 0x01         # Card is locked (password set, needs auth)
    AUTHENTICATED = 0x03  # Card is authenticated (session active)


class AuthResult(IntEnum):
    """Authentication result (from header offset 0x1C0)."""
    NONE = 0x00           # No auth attempted
    SUCCESS = 0x03        # Authentication successful


# Pre-computed patterns (CRC verified from traces)
ENTER_CRC = 0x3CE8
LEAVE_CRC = 0x21F1


# =============================================================================
# Mersenne Twister PRNG (matches libSecure.dll implementation)
# =============================================================================

class TRandomMersenne:
    """Mersenne Twister PRNG matching libSecure.dll implementation."""
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


# =============================================================================
# Password Encoding Functions
# =============================================================================

def _build_seed(scramble_key: bytes, milliseconds: int) -> int:
    """Build PRNG seed from scramble key and milliseconds."""
    return (scramble_key[0] << 24) | (scramble_key[2] << 16) | (scramble_key[4] << 8) | (milliseconds & 0xFFFF)


def _prng_xor(buf: bytearray, seed: int):
    """XOR buffer with 128 PRNG DWORDs."""
    mt = TRandomMersenne(seed)
    for i in range(128):
        rand_val = mt.irandom(0, 0x7FFFFFFE)
        for j in range(4):
            buf[i*4 + j] ^= (rand_val >> (j*8)) & 0xFF


def _cbitarray_test(data: bytes, bit_index: int) -> int:
    """Test bit in byte array."""
    return (data[bit_index >> 3] >> (bit_index & 7)) & 1


def _cbitarray_set(data: bytearray, bit_index: int, value: int):
    """Set bit in byte array."""
    byte_idx = bit_index >> 3
    bit_in_byte = bit_index & 7
    if value:
        data[byte_idx] |= (1 << bit_in_byte)
    else:
        data[byte_idx] &= ~(1 << bit_in_byte)


def _permute(scramble_key: bytes, password_vector: bytearray, buf: bytearray):
    """Apply bit permutation using scramble_key and password_vector."""
    start_offset = scramble_key[0]
    base_offset = scramble_key[1] & 7
    output_view = memoryview(buf)[start_offset:start_offset+256]
    output_counter = 0
    password_byte = password_vector[0]

    for i in range(64):
        if i != 0 and (output_counter & 7) == 0:
            password_byte = password_vector[i >> 1]
        scramble_bit = _cbitarray_test(scramble_key, i)
        for j in range(4):
            bit_position = (output_counter * 8 + j * 8) | base_offset
            password_bit = (password_byte >> 7) & 1
            if scramble_bit == 1:
                output_bit = password_bit
            else:
                output_bit = 1 - password_bit
            _cbitarray_set(output_view, bit_position, output_bit)
            password_byte = (password_byte << 1) & 0xFF
        output_counter += 4


def _compute_checksum(buf: bytearray):
    """Compute checksum: sum of 255 byte-swapped 16-bit words, stored BE at 510-511."""
    checksum = 0
    for i in range(255):
        word = buf[i*2] | (buf[i*2 + 1] << 8)
        word = ((word << 8) | (word >> 8)) & 0xFFFF
        checksum = (checksum + word) & 0xFFFF
    buf[510] = (checksum >> 8) & 0xFF
    buf[511] = checksum & 0xFF


# =============================================================================
# Enter/Leave Mode Patterns
# =============================================================================

def build_enter_pattern(identifier: bytes) -> bytes:
    """
    Build the Enter Mode pattern (512 bytes).

    Args:
        identifier: 8-byte card identifier (e.g., b"69668301")

    Returns:
        512-byte buffer for CMD24 to LBA 0
    """
    if len(identifier) != 8:
        raise ValueError("Identifier must be 8 bytes")

    id_reversed = identifier[::-1]
    buf = bytearray(512)

    buf[0x000:0x008] = identifier
    buf[0x0F8:0x100] = id_reversed
    buf[0x100] = 0x02
    buf[0x101] = 0x01
    buf[0x1FE] = 0x01
    buf[0x1FF] = 0x02

    return bytes(buf)


def build_leave_pattern(identifier: bytes) -> bytes:
    """
    Build the Leave Mode pattern (512 bytes).

    Args:
        identifier: 8-byte card identifier (e.g., b"69668301")

    Returns:
        512-byte buffer for CMD24 to LBA 0
    """
    if len(identifier) != 8:
        raise ValueError("Identifier must be 8 bytes")

    id_reversed = identifier[::-1]
    buf = bytearray(512)

    buf[0x000:0x008] = id_reversed
    buf[0x0F8:0x100] = identifier
    buf[0x100] = 0x02
    buf[0x101] = 0x00
    buf[0x106] = 0x01
    buf[0x107] = 0x02
    buf[0x1F8] = 0x02
    buf[0x1F9] = 0x01

    return bytes(buf)


# =============================================================================
# XMaskHeader - Parsed Security Header
# =============================================================================

class XMaskHeader:
    """Parsed security header from LBA 5."""

    # Scramble key offset formula: 0xB8 + header[0x3C] + header[0x44]
    SCRAMBLE_KEY_BASE = 0xB8

    def __init__(self, data: bytes):
        if len(data) != 512:
            raise ValueError("Header must be 512 bytes")

        # Store FULL header - needed for scramble key extraction
        self.raw = data

        # Parse header fields
        self.magic = data[0:3].decode('ascii', errors='replace')
        self.model = data[3:12].decode('ascii', errors='replace').rstrip('\x00')

        # Index values for scramble key lookup
        self.index_a = data[0x3C]
        self.index_b = data[0x44]

        # Auth result at offset 0x49
        self.auth_result = data[0x49]

        # Status at offset 0x1C0, 0x1C1
        self.status_0 = data[0x1C0]
        self.status_1 = data[0x1C1]

    @property
    def is_pro(self) -> bool:
        """Check if this is X-MASK PRO (ET1289) vs X-MASK (ET1288)."""
        return 'ET1289' in self.model

    def get_scramble_key(self) -> bytes:
        """
        Extract 8-byte scramble key from header.

        Formula: key[i] = header[0xB8 + ((index_a + index_b + i) & 0xFF)]

        Each byte index is truncated to 8 bits before adding to base 0xB8,
        causing wraparound when (index_a + index_b + i) >= 256.

        Returns:
            8-byte scramble key
        """
        sum_idx = self.index_a + self.index_b
        key = bytearray(8)
        for i in range(8):
            offset = self.SCRAMBLE_KEY_BASE + ((sum_idx + i) & 0xFF)
            key[i] = self.raw[offset]
        return bytes(key)

    @property
    def scramble_key_offset(self) -> int:
        """Get the calculated scramble key offset for key[0]."""
        return self.SCRAMBLE_KEY_BASE + ((self.index_a + self.index_b) & 0xFF)

    @property
    def is_zeros_header(self) -> bool:
        """Check if this is a 'zeros' header (first read returns zeros)."""
        return self.index_a == 0x00

    @property
    def has_valid_key(self) -> bool:
        """Check if header has valid (non-zero) scramble key."""
        if self.is_zeros_header:
            return False
        try:
            key = self.get_scramble_key()
            return key != bytes(8)
        except ValueError:
            return False

    @property
    def auth_success(self) -> bool:
        """Check if last authentication was successful."""
        return self.status_1 == CardStatus.AUTHENTICATED

    @property
    def needs_auth(self) -> bool:
        """Check if authentication is required."""
        return self.status_1 == CardStatus.LOCKED

    @property
    def is_locked(self) -> bool:
        """Check if card is locked (mask mode enabled)."""
        return self.status_1 == CardStatus.LOCKED

    @property
    def is_unlocked(self) -> bool:
        """Check if card is unlocked (no password set)."""
        return self.status_1 == CardStatus.UNLOCKED

    def __repr__(self):
        return (f"XMaskHeader(magic={self.magic!r}, model={self.model!r}, "
                f"key_offset=0x{self.scramble_key_offset:X}, "
                f"auth_result=0x{self.auth_result:02X}, status=0x{self.status_1:02X})")


# =============================================================================
# XMask Protocol Handler
# =============================================================================

class XMask:
    """
    X-Mask / X-Mask PRO protocol handler.

    IMPORTANT: Each password operation reads a FRESH header immediately
    before encoding and writing, because the scramble key changes on every read.

    Usage:
        from sdio_host import SDIOHost
        from flexxon_lib.xmask import XMask

        sd = SDIOHost()
        sd.init()
        sd.initialize_card()

        xmask = XMask(sd, identifier=b"69668301")

        # Read status
        header, timing = xmask.read_status()
        print(header)

        # Authenticate
        success, timing = xmask.authenticate(b"P4ssw0rd!")
        if success:
            print("Auth success!")

        # Temporary unlock (requires prior auth)
        success, timing = xmask.temp_unlock(b"P4ssw0rd!")
        if success:
            print("Temp unlock success!")
    """

    def __init__(self, sd_host, identifier: bytes = SERIAL):
        """
        Initialize X-Mask protocol handler.

        Args:
            sd_host: SDIOHost instance (must be initialized with card selected)
            identifier: 8-byte card identifier (ASCII, e.g., b"69668301")
        """
        if len(identifier) != 8:
            raise ValueError("Identifier must be exactly 8 bytes")

        self.sd = sd_host
        self.identifier = identifier
        self._is_pro = None  # Detected on first header read

        # Pre-build mode patterns
        self._enter_pattern = build_enter_pattern(identifier)
        self._leave_pattern = build_leave_pattern(identifier)

    # =========================================================================
    # Low-level Operations
    # =========================================================================

    def enter_mode(self):
        """Enter special mode (Enter x2, Leave, Enter)."""
        self.sd.write_block(LBA_MODE, self._enter_pattern)
        self.sd.write_block(LBA_MODE, self._enter_pattern)
        self.sd.write_block(LBA_MODE, self._leave_pattern)
        self.sd.write_block(LBA_MODE, self._enter_pattern)

    def leave_mode(self):
        """Leave special mode (Enter, Leave)."""
        self.sd.write_block(LBA_MODE, self._enter_pattern)
        self.sd.write_block(LBA_MODE, self._leave_pattern)

    def read_header_raw(self) -> bytes:
        """Read raw 512-byte header from LBA 5."""
        return self.sd.read_block(LBA_HEADER)

    def read_header(self) -> XMaskHeader:
        """Read and parse header from LBA 5."""
        return XMaskHeader(self.read_header_raw())

    def read_header_with_key(self, max_attempts: int = 5) -> XMaskHeader:
        """
        Read header multiple times to get one with valid scramble key.

        The first LBA 5 read often returns a 'zeros' header.
        Subsequent reads return the actual header with scramble key.

        Returns:
            XMaskHeader with valid scramble key
        """
        import time

        for attempt in range(max_attempts):
            # Read header twice per attempt
            header1 = self.read_header()
            header2 = self.read_header()

            if header2.has_valid_key:
                result = header2
                break
            elif header1.has_valid_key:
                result = header1
                break

            # Small delay before retry
            time.sleep(0.05)
        else:
            raise RuntimeError("Failed to read header with valid scramble key")

        # Detect card type on first successful header read
        if self._is_pro is None:
            self._is_pro = result.is_pro

        return result

    # =========================================================================
    # Password Encoding
    # =========================================================================

    def encode_password_buffer(self, password: bytes, scramble_key: bytes,
                                lba: int, milliseconds: int = None) -> bytes:
        """
        Encode password buffer for specified LBA operation.

        Args:
            password: Password bytes (max 32 bytes)
            scramble_key: 8-byte scramble key from header
            lba: Target LBA (6=auth, 7=remove, 8=set, 9=partition, 10=temp_unlock)
            milliseconds: Time component (0-999), uses current time if None

        Returns:
            512-byte encoded buffer ready to write
        """
        if len(scramble_key) != 8:
            raise ValueError("Scramble key must be 8 bytes")

        if milliseconds is None:
            milliseconds = int(time.time() * 1000) % 1000

        # Initialize buffer
        buf = bytearray(512)
        buf[0:8] = self.identifier
        buf[248:256] = self.identifier[::-1]

        # Set buf[256] based on operation type and card model
        # X-MASK (ET1288): AUTH uses 0x02
        # X-MASK PRO (ET1289): AUTH uses 0x00
        if lba == LBA_AUTH:
            buf[256] = 0x00 if self._is_pro else 0x02
        elif lba == LBA_REMOVE_PW:
            buf[256] = 0x02
        elif lba == LBA_SET_PW:
            buf[256] = 0x22
        elif lba == LBA_SET_PW_ALT:
            buf[256] = 0x02
        elif lba == LBA_TEMP_UNLOCK:
            buf[256] = 0x02
        else:
            buf[256] = 0x00

        buf[257] = 0x01

        # Apply PRNG XOR
        seed = _build_seed(scramble_key, milliseconds)
        _prng_xor(buf, seed)

        # Build password_vector
        password_vector = bytearray(32)
        pw_len = min(len(password), 32)
        password_vector[0:pw_len] = password[:pw_len]

        # Extra bytes for X-MASK PRO only (ET1289)
        # X-MASK (ET1288) does NOT use these extra bytes
        if lba == LBA_AUTH and self._is_pro:
            password_vector[20] = 0x0F
            password_vector[21] = 0x0F
            password_vector[25] = 0x0F
            password_vector[27] = 0xF0

        # Apply permutation
        _permute(scramble_key, password_vector, buf)

        # Compute checksum
        _compute_checksum(buf)

        return bytes(buf)

    # =========================================================================
    # High-level Operations
    # =========================================================================

    def read_status(self):
        """
        Full status read sequence.

        Returns:
            (XMaskHeader, timing_dict)
        """
        timing = {}
        timing['start'] = self.sd.get_cycle_count()
        self.enter_mode()
        timing['enter_mode'] = self.sd.get_cycle_count()
        header = self.read_header_with_key()
        timing['read_header'] = self.sd.get_cycle_count()
        self.leave_mode()
        timing['leave_mode'] = self.sd.get_cycle_count()
        return header, timing

    def authenticate(self, password: bytes, debug: bool = False):
        """
        Authenticate with password.

        Returns:
            (success, timing_dict)
        """
        timing = {}
        timing['start'] = self.sd.get_cycle_count()

        self.enter_mode()
        timing['enter_mode'] = self.sd.get_cycle_count()

        header = self.read_header_with_key()
        scramble_key = header.get_scramble_key()
        timing['read_header'] = self.sd.get_cycle_count()
        if debug:
            print(f"  [DEBUG] Auth: key={scramble_key.hex()}, is_pro={self._is_pro}")

        encoded = self.encode_password_buffer(password, scramble_key, LBA_AUTH)
        if debug:
            print(f"  [DEBUG] Auth: encoded[0:16]={encoded[:16].hex()}")
            print(f"  [DEBUG] Auth: encoded[256:260]={encoded[256:260].hex()}")
        self.sd.write_block(LBA_AUTH, encoded)
        timing['password_write'] = self.sd.get_cycle_count()

        self.leave_mode()
        timing['leave_mode'] = self.sd.get_cycle_count()

        result_header, status_timing = self.read_status()
        timing['read_status'] = status_timing

        if debug:
            print(f"  [DEBUG] Auth result: status=0x{result_header.status_1:02X}")

        return result_header.auth_success, timing

    def remove_password(self, password: bytes):
        """
        Remove password (disable mask mode).

        Returns:
            (success, timing_dict)
        """
        timing = {}
        timing['start'] = self.sd.get_cycle_count()

        auth_success, auth_timing = self.authenticate(password)
        timing['auth'] = auth_timing
        if not auth_success:
            return False, timing

        self.enter_mode()
        timing['enter_mode'] = self.sd.get_cycle_count()

        header = self.read_header_with_key()
        scramble_key = header.get_scramble_key()
        timing['read_header'] = self.sd.get_cycle_count()

        encoded = self.encode_password_buffer(password, scramble_key, LBA_REMOVE_PW)
        self.sd.write_block(LBA_REMOVE_PW, encoded)
        timing['remove_write'] = self.sd.get_cycle_count()

        self.leave_mode()
        timing['leave_mode'] = self.sd.get_cycle_count()

        result_header, status_timing = self.read_status()
        timing['read_status'] = status_timing
        return not result_header.is_locked, timing

    def set_password(self, password: bytes, power_cycle: bool = True, debug: bool = False):
        """
        Set new password (enable mask mode).

        Returns:
            (success, timing_dict)
        """
        import time
        timing = {}
        timing['start'] = self.sd.get_cycle_count()

        self.enter_mode()
        timing['step1_enter'] = self.sd.get_cycle_count()
        header = self.read_header_with_key()
        scramble_key1 = header.get_scramble_key()
        timing['step1_read'] = self.sd.get_cycle_count()
        if debug:
            print(f"  [DEBUG] Step 1: key1={scramble_key1.hex()}")
        self.leave_mode()
        timing['step1_leave'] = self.sd.get_cycle_count()

        self.enter_mode()
        timing['step2_enter'] = self.sd.get_cycle_count()
        encoded = self.encode_password_buffer(password, scramble_key1, LBA_SET_PW_ALT)
        if debug:
            print(f"  [DEBUG] Step 2: Write LBA 9, first 16 bytes={encoded[:16].hex()}")
        self.sd.write_block(LBA_SET_PW_ALT, encoded)
        timing['step2_write'] = self.sd.get_cycle_count()
        self.leave_mode()
        timing['step2_leave'] = self.sd.get_cycle_count()

        self.enter_mode()
        timing['step3_enter'] = self.sd.get_cycle_count()
        header = self.read_header_with_key()
        scramble_key2 = header.get_scramble_key()
        timing['step3_read'] = self.sd.get_cycle_count()
        if debug:
            print(f"  [DEBUG] Step 3: key2={scramble_key2.hex()}")
        self.leave_mode()
        timing['step3_leave'] = self.sd.get_cycle_count()

        self.enter_mode()
        timing['step4_enter'] = self.sd.get_cycle_count()
        encoded = self.encode_password_buffer(password, scramble_key2, LBA_SET_PW)
        if debug:
            print(f"  [DEBUG] Step 4: Write LBA 8, first 16 bytes={encoded[:16].hex()}")
        self.sd.write_block(LBA_SET_PW, encoded)
        timing['step4_write'] = self.sd.get_cycle_count()
        self.leave_mode()
        timing['step4_leave'] = self.sd.get_cycle_count()

        if power_cycle:
            self.sd.power_cycle(off_time_ms=200)
            time.sleep(0.3)
            self.sd.initialize_card()

        result_header, status_timing = self.read_status()
        timing['read_status'] = status_timing
        if debug:
            print(f"  [DEBUG] Final status: 0x{result_header.status_1:02X}, is_locked={result_header.is_locked}")
        return result_header.is_locked, timing

    def temp_unlock(self, password: bytes):
        """
        Temporarily unlock card.

        Returns:
            (success, timing_dict)
        """
        timing = {}
        timing['start'] = self.sd.get_cycle_count()

        auth_result, auth_timing = self.authenticate(password)
        timing['auth'] = auth_timing

        if not auth_result:
            return False, timing

        self.enter_mode()
        timing['enter_mode'] = self.sd.get_cycle_count()

        header = self.read_header_with_key()
        scramble_key = header.get_scramble_key()
        timing['read_header'] = self.sd.get_cycle_count()

        encoded = self.encode_password_buffer(password, scramble_key, LBA_TEMP_UNLOCK)
        self.sd.write_block(LBA_TEMP_UNLOCK, encoded)
        timing['temp_unlock_write'] = self.sd.get_cycle_count()

        self.leave_mode()
        timing['leave_mode'] = self.sd.get_cycle_count()

        result_header, status_timing = self.read_status()
        timing['read_status'] = status_timing

        return result_header.auth_success, timing

    def get_card_info(self) -> dict:
        """
        Get card information.

        Returns:
            Dictionary with card details
        """
        header, _ = self.read_status()
        try:
            scramble_key = header.get_scramble_key()
            key_hex = scramble_key.hex()
        except ValueError as e:
            key_hex = f"ERROR: {e}"

        return {
            'identifier': self.identifier.decode('ascii', errors='replace'),
            'magic': header.magic,
            'model': header.model,
            'scramble_key_offset': f"0x{header.scramble_key_offset:X}",
            'scramble_key': key_hex,
            'index_a': f"0x{header.index_a:02X}",
            'index_b': f"0x{header.index_b:02X}",
            'auth_result': f"0x{header.auth_result:02X}",
            'status': f"0x{header.status_1:02X}",
            'is_locked': header.is_locked,
            'auth_success': header.auth_success,
        }


# =============================================================================
# Utility Functions
# =============================================================================

def hexdump(data: bytes, offset: int = 0, length: int = 256) -> str:
    """Pretty-print hex dump of data."""
    lines = []
    for i in range(0, min(len(data), length), 16):
        hex_part = ' '.join(f'{b:02X}' for b in data[i:i+16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
        lines.append(f'{offset+i:04X}: {hex_part:<48} {ascii_part}')
    return '\n'.join(lines)


# =============================================================================
# Main - Test Pattern Generation
# =============================================================================

if __name__ == '__main__':
    identifier = SERIAL

    enter = build_enter_pattern(identifier)
    leave = build_leave_pattern(identifier)

    print("=== Enter Pattern ===")
    print(hexdump(enter, 0, 32))
    print("...")
    print(hexdump(enter[0xF0:], 0xF0, 32))
    print("...")
    print(hexdump(enter[0x1F0:], 0x1F0, 16))

    print("\n=== Leave Pattern ===")
    print(hexdump(leave, 0, 32))
    print("...")
    print(hexdump(leave[0xF0:], 0xF0, 32))
    print("...")
    print(hexdump(leave[0x1F0:], 0x1F0, 16))

    print("\n=== Scramble Key Offset Test ===")
    # Test with known values from traces
    test_cases = [
        (0x3A, 0x36, 0x128),  # Earlier traces
        (0x3A, 0x3D, 0x12F),  # v7 traces
        (0x30, 0x3D, 0x125),  # v7 traces
        (0x3A, 0x51, 0x143),  # v7 traces
    ]
    for idx_a, idx_b, expected in test_cases:
        calculated = 0xB8 + idx_a + idx_b
        status = "OK" if calculated == expected else "FAIL"
        print(f"  [0x3C]=0x{idx_a:02X}, [0x44]=0x{idx_b:02X} -> 0x{calculated:X} (expected 0x{expected:X}) [{status}]")
