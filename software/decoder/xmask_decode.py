#!/usr/bin/env python3
"""X-MASK protocol decoding functions - uses flexxon_lib."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "flexxon_lib"))

from xmask import (
    TRandomMersenne, _build_seed as build_seed,
    XMaskHeader, LBA_MODE, LBA_HEADER, LBA_AUTH,
    LBA_REMOVE_PW, LBA_SET_PW, LBA_SET_PW_ALT, LBA_TEMP_UNLOCK
)

LBA_NAMES = {
    0: "MODE",
    5: "HEADER",
    6: "AUTH",
    7: "REMOVE_PW",
    8: "SET_PW",
    9: "SET_PW_ALT",
    10: "TEMP_UNLOCK",
}


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert '0x...' or raw hex string to bytes."""
    if hex_str.startswith('0x'):
        hex_str = hex_str[2:]
    return bytes.fromhex(hex_str)


def get_prng_stream(seed: int) -> bytes:
    """Generate 512-byte PRNG stream."""
    mt = TRandomMersenne(seed)
    stream = bytearray(512)
    for i in range(128):
        rand_val = mt.irandom(0, 0x7FFFFFFE)
        for j in range(4):
            stream[i*4 + j] = (rand_val >> (j*8)) & 0xFF
    return bytes(stream)


def xor_buffers(a: bytes, b: bytes) -> bytes:
    """XOR two byte buffers."""
    return bytes(x ^ y for x, y in zip(a, b))


def parse_header(data: bytes) -> dict:
    """Parse LBA 5 header using XMaskHeader."""
    if len(data) != 512:
        return {'error': f'Invalid size: {len(data)}'}

    header = XMaskHeader(data)

    try:
        scramble_key = header.get_scramble_key()
    except ValueError:
        scramble_key = b'\x00' * 8

    return {
        'magic': header.magic,
        'model': header.model,
        'index_a': header.index_a,
        'index_b': header.index_b,
        'scramble_key_offset': header.scramble_key_offset,
        'scramble_key': scramble_key,
        'status_0': header.status_0,
        'status_1': header.status_1,
        'auth_result': header.auth_result,
        'is_locked': header.is_locked,
        'is_unlocked': header.is_unlocked,
        'is_authenticated': header.auth_success,
    }


def decode_auth_buffer(data: bytes, scramble_key: bytes, serial: bytes) -> dict:
    """Attempt to decode LBA 6/7/8/9/10 buffer."""
    if len(data) != 512:
        return {'valid': False, 'error': f'Invalid size: {len(data)}'}

    for ms in range(1000):
        seed = build_seed(scramble_key, ms)
        prng = get_prng_stream(seed)
        decrypted = xor_buffers(data, prng)

        if decrypted[0:8] == serial:
            return {
                'valid': True,
                'ms_value': ms,
                'decoded_serial': decrypted[0:8],
                'buf_248_256': decrypted[248:256],
                'buf_256': decrypted[256],
                'buf_257': decrypted[257],
            }

    return {'valid': False, 'ms_value': None, 'error': 'No matching ms value found'}


def get_lba_name(lba: int) -> str:
    """Return human name for LBA."""
    return LBA_NAMES.get(lba, f"LBA_{lba}")


def parse_mode_buffer(data: bytes) -> dict:
    """Parse LBA 0 mode buffer to determine enter/leave."""
    if len(data) != 512:
        return {'type': 'UNKNOWN', 'error': 'Invalid size'}

    id_bytes = data[0:8]
    id_reversed = data[0xF8:0x100]
    byte_256 = data[0x100]
    byte_257 = data[0x101]
    byte_510 = data[0x1FE]
    byte_511 = data[0x1FF]

    # Check for ENTER pattern
    if id_bytes == id_reversed[::-1] and byte_256 == 0x02 and byte_257 == 0x01:
        if byte_510 == 0x01 and byte_511 == 0x02:
            return {'type': 'ENTER', 'identifier': id_bytes.decode('ascii', errors='replace')}

    # Check for LEAVE pattern
    if id_bytes == id_reversed[::-1] and byte_256 == 0x02 and byte_257 == 0x00:
        return {'type': 'LEAVE', 'identifier': id_reversed.decode('ascii', errors='replace')}

    return {'type': 'UNKNOWN'}
