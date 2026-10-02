#!/usr/bin/env python3
"""
Swissbit SDIO security commands via FSI protocol

Based on reverse engineering of libCardManagement.so:
- FSI communication via sector 4 (byte offset 0x800)
- FSI block format: [32-byte Identifier][direction][flags][length_lo][length_hi][APDU]
- Response format: [direction][flags][length_hi][length_lo][data+SW] (length is big-endian!)
- APDU format: CLA=0xFF, INS, P1, P2, Le
- SW 0x9000 = success, 0x6700 = wrong length
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "greatfet"))
from sdio_host import SDIOHost

# FSI communication sector
FSI_SECTOR = 4  # Byte offset 0x800 / 512 = 4

# Swissbit APDU class byte
CLA = 0xFF

# INS codes
INS_ACTIVATE = 0x10
INS_DEACTIVATE = 0x20
INS_VERIFY = 0x30
INS_LOCK = 0x31
INS_CHANGE_PASSWORD = 0x40
INS_RESET = 0x53
INS_GET = 0x70

# GET subcommands (P1 values for INS_GET)
GET_STATUS = 0x00
GET_CARD_ID = 0x01
GET_APP_VERSION = 0x02
GET_CHALLENGE = 0x05
GET_CONTROLLER_ID = 0x06

# The 32-byte Identifier from libCardManagement.so
IDENTIFIER = bytes([
    0x10, 0x6a, 0xf8, 0x1a, 0xd6, 0xf8, 0xc8, 0x70,
    0xac, 0x7e, 0x85, 0xf0, 0xe9, 0x9e, 0xf3, 0x9d,
    0x1e, 0x11, 0xa1, 0xba, 0x87, 0x4a, 0xc6, 0xdb,
    0x42, 0x81, 0x15, 0x8e, 0xfe, 0x6d, 0x3c, 0x81
])


def build_fsi_block(direction, apdu):
    """Build FSI protocol block with identifier"""
    block = bytearray(512)
    # Identifier at offset 0
    block[0:32] = IDENTIFIER
    # Direction at offset 0x20
    block[0x20] = direction
    # Flags at offset 0x21 (0x00 for small data)
    block[0x21] = 0x00
    # Length at offset 0x22-0x23 (little-endian in send block)
    block[0x22] = len(apdu) & 0xFF
    block[0x23] = (len(apdu) >> 8) & 0xFF
    # APDU at offset 0x24
    block[0x24:0x24+len(apdu)] = apdu
    return bytes(block)


def parse_fsi_response(data):
    """Parse FSI response block"""
    direction = data[0]
    flags = data[1]
    length = (data[2] << 8) | data[3]  # Big-endian in response!
    print(f"  Direction: 0x{direction:02X}, Flags: 0x{flags:02X}, Length: {length}")
    if length > 0 and length <= 500:
        resp_data = data[4:4+length]
        print(f"  Data: {resp_data.hex()}")
        if length >= 2:
            sw = (resp_data[-2] << 8) | resp_data[-1]
            print(f"  SW: 0x{sw:04X}")
            return sw, resp_data[:-2] if length > 2 else b''
    return None, None


class SwissbitSDIO:
    """Direct SDIO communication with Swissbit secure SD cards"""

    def __init__(self, sdio=None):
        self.sdio = sdio or SDIOHost()

    def init_card(self, clock_divider=255):
        """Initialize SDIO and SD card"""
        self.sdio.init(clock_divider)
        return self.sdio.initialize_card()

    def fsi_request(self):
        """
        Send FSI_REQUEST to initialize smart card interface.
        This is equivalent to an ATR request in smart card terms.
        Uses FC mode (direction=0), expects response direction=2.
        """
        # FSI_REQUEST_SE command (5 bytes)
        request_cmd = b"FSI_REQUEST_SE"[:5]  # Just first 5 bytes needed

        # Build FSI block with direction=0 (FC mode)
        block = bytearray(512)
        block[0:32] = IDENTIFIER
        block[0x20] = 0x00  # FC mode
        block[0x21] = 0x00  # flags
        block[0x22] = len(request_cmd) & 0xFF
        block[0x23] = (len(request_cmd) >> 8) & 0xFF
        block[0x24:0x24+len(request_cmd)] = request_cmd

        self.sdio.write_block(FSI_SECTOR, bytes(block))
        data = self.sdio.read_block(FSI_SECTOR)

        # Parse response (expect direction=2 for FC response)
        direction = data[0]
        flags = data[1]
        length = (data[2] << 8) | data[3]
        print(f"  FSI_REQUEST response: dir=0x{direction:02X}, len={length}")

        if length > 0 and length <= 500:
            resp_data = data[4:4+length]
            print(f"  ATR/Response: {resp_data.hex()}")
            if length >= 2:
                sw = (resp_data[-2] << 8) | resp_data[-1]
                print(f"  SW: 0x{sw:04X}")
                return sw == 0x9000, resp_data
        return False, None

    def fsi_send_apdu(self, apdu):
        """Send APDU via FSI at sector 4"""
        fsi_block = build_fsi_block(0x01, apdu)
        self.sdio.write_block(FSI_SECTOR, fsi_block)
        data = self.sdio.read_block(FSI_SECTOR)
        return parse_fsi_response(data)

    def get_status(self, le=0x10):
        """Get card security status"""
        apdu = bytes([CLA, INS_GET, GET_STATUS, 0x00, le])
        return self.fsi_send_apdu(apdu)

    def get_card_id(self, le=0x20):
        """Get card ID"""
        apdu = bytes([CLA, INS_GET, GET_CARD_ID, 0x00, le])
        return self.fsi_send_apdu(apdu)

    def get_app_version(self, le=0x10):
        """Get application version"""
        apdu = bytes([CLA, INS_GET, GET_APP_VERSION, 0x00, le])
        return self.fsi_send_apdu(apdu)

    def get_challenge(self, le=0x10):
        """Get challenge for authentication"""
        apdu = bytes([CLA, INS_GET, GET_CHALLENGE, 0x00, le])
        return self.fsi_send_apdu(apdu)

    def get_controller_id(self, le=0x10):
        """Get controller ID"""
        apdu = bytes([CLA, INS_GET, GET_CONTROLLER_ID, 0x00, le])
        return self.fsi_send_apdu(apdu)


def main():
    print("=== Swissbit SDIO Test ===\n")

    sb = SwissbitSDIO()

    if not sb.init_card():
        print("Card init failed")
        return

    # Check card status first
    print("\n=== Card Status (CMD13) ===")
    status = sb.sdio.cmd13_send_status()
    if status:
        print(f"Raw status: 0x{status:08X}")
        state = (status >> 9) & 0xF
        states = {0:'idle', 1:'ready', 2:'ident', 3:'stby', 4:'tran', 5:'data', 6:'rcv', 7:'prg', 8:'dis'}
        print(f"State: {states.get(state, 'unknown')} ({state})")
        print(f"Ready for data: {bool((status >> 8) & 1)}")
        print(f"Card locked: {bool((status >> 25) & 1)}")

    # Set block length
    sb.sdio.cmd16_set_blocklen(512)

    # FSI Tests via Sector 4
    print("\n" + "="*60)
    print("=== FSI Protocol Tests (Sector 4) ===")
    print("="*60)

    # First try to read sector 4 to check accessibility
    print("\n--- Check Sector 4 accessibility ---")
    try:
        data = sb.sdio.read_block(FSI_SECTOR)
        print(f"  Sector 4 readable: {data[:32].hex()}")
    except Exception as e:
        print(f"  Sector 4 NOT accessible: {e}")
        print("  Card may need power cycle or different initialization")

    # Try FSI_REQUEST to initialize
    print("\n--- FSI_REQUEST (ATR) ---")
    try:
        success, atr = sb.fsi_request()
        if success:
            print("  FSI initialized successfully!")
        else:
            print("  FSI_REQUEST returned non-9000 SW")
    except Exception as e:
        print(f"  Error: {e}")

    # Test different Le values for GET_STATUS
    print("\n--- GET_STATUS tests ---")
    for le in [0x00, 0x02, 0x04, 0x08, 0x10, 0x20]:
        print(f"\nGET_STATUS with Le=0x{le:02X}:")
        try:
            sw, data = sb.get_status(le)
            if sw == 0x9000:
                print(f"  SUCCESS! Data: {data.hex() if data else 'empty'}")
        except Exception as e:
            print(f"  Error: {e}")

    # Test other GET commands
    print("\n--- Other GET commands ---")

    print("\nGET_CARD_ID:")
    try:
        sw, data = sb.get_card_id()
        if sw == 0x9000:
            print(f"  Card ID: {data.hex() if data else 'empty'}")
    except Exception as e:
        print(f"  Error: {e}")

    print("\nGET_APP_VERSION:")
    try:
        sw, data = sb.get_app_version()
        if sw == 0x9000:
            print(f"  Version: {data.hex() if data else 'empty'}")
    except Exception as e:
        print(f"  Error: {e}")

    print("\nGET_CHALLENGE:")
    try:
        sw, data = sb.get_challenge()
        if sw == 0x9000:
            print(f"  Challenge: {data.hex() if data else 'empty'}")
    except Exception as e:
        print(f"  Error: {e}")

    print("\nGET_CONTROLLER_ID:")
    try:
        sw, data = sb.get_controller_id()
        if sw == 0x9000:
            print(f"  Controller ID: {data.hex() if data else 'empty'}")
    except Exception as e:
        print(f"  Error: {e}")

    # Try raw APDU without identifier
    print("\n--- Testing without identifier ---")
    print("\nRaw APDU at sector 4 (no identifier):")
    apdu = bytes([0xFF, 0x70, 0x00, 0x00, 0x10])
    raw_block = apdu + bytes(512 - len(apdu))
    try:
        sb.sdio.write_block(FSI_SECTOR, raw_block)
        data = sb.sdio.read_block(FSI_SECTOR)
        print(f"  Response: {data[:32].hex()}")
        parse_fsi_response(data)
    except Exception as e:
        print(f"  Error: {e}")


if __name__ == '__main__':
    main()
