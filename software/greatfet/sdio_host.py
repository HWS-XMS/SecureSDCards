#!/usr/bin/env python3
"""
SDIO Host Controller for GreatFET One
Allows controlling SDIO clock speed and sending commands for protocol analysis
"""

import sys
from greatfet import GreatFET

# SDIO Class number (must match firmware)
SDIO_CLASS = 0x120

# Command flags
FLAG_RESPONSE_EXPECT = (1 << 6)
FLAG_RESPONSE_LONG   = (1 << 7)
FLAG_CHECK_CRC       = (1 << 8)
FLAG_DATA_EXPECTED   = (1 << 9)
FLAG_WRITE           = (1 << 10)

# Common SD Commands
CMD0_GO_IDLE_STATE        = 0
CMD2_ALL_SEND_CID         = 2
CMD3_SEND_RELATIVE_ADDR   = 3
CMD7_SELECT_CARD          = 7
CMD8_SEND_IF_COND         = 8
CMD9_SEND_CSD             = 9
CMD10_SEND_CID            = 10
CMD13_SEND_STATUS         = 13
CMD16_SET_BLOCKLEN        = 16
CMD17_READ_SINGLE_BLOCK   = 17
CMD55_APP_CMD             = 55
ACMD6_SET_BUS_WIDTH       = 6
ACMD41_SD_SEND_OP_COND    = 41


class SDIOHost(object):
    """SDIO Host controller using GreatFET"""

    def __init__(self, gf=None):
        self.gf = gf or GreatFET()
        self.rca = 0  # Relative Card Address

    def init(self, clock_divider=255):
        """
        Initialize SDIO peripheral.

        Clock frequency = base_clock / (2 * (divider + 1))
        With ~50MHz base clock:
          divider=255 -> ~98kHz   (good for debugging)
          divider=100 -> ~247kHz
          divider=50  -> ~490kHz
          divider=25  -> ~961kHz  (standard init speed)
          divider=10  -> ~2.27MHz
          divider=1   -> ~12.5MHz
          divider=0   -> ~25MHz   (full speed)
        """
        result = self.gf.comms.execute_command(SDIO_CLASS, 0x0, '<B', '<i', clock_divider)
        status = result[0] if isinstance(result, tuple) else result
        if status != 0:
            raise RuntimeError(f"SDIO init failed: {status}")
        print(f"SDIO initialized with clock divider {clock_divider}")

    def set_clock(self, divider):
        """Set clock divider (0-255)"""
        result = self.gf.comms.execute_command(SDIO_CLASS, 0x1, '<B', '<i', divider)
        status = result[0] if isinstance(result, tuple) else result
        if status != 0:
            raise RuntimeError(f"Set clock failed: {status}")

    def set_bus_width(self, width):
        """Set bus width (1 or 4)"""
        result = self.gf.comms.execute_command(SDIO_CLASS, 0x2, '<B', '<i', width)
        status = result[0] if isinstance(result, tuple) else result
        if status != 0:
            raise RuntimeError(f"Set bus width failed: {status}")

    def send_command(self, cmd_index, argument=0, flags=0):
        """
        Send an SD command.
        Returns (status, response[4])
        """
        result = self.gf.comms.execute_command(SDIO_CLASS, 0x3, '<BII', '<iIIII',
                                               cmd_index, argument, flags)
        status, r0, r1, r2, r3 = result
        return status, (r0, r1, r2, r3)

    def get_status(self):
        """Get SDIO peripheral status"""
        result = self.gf.comms.execute_command(SDIO_CLASS, 0x4, '', '<IIIBBB')
        status, rintsts, cdetect, init, width, divider = result
        return {
            'status': hex(status),
            'interrupts': hex(rintsts),
            'card_detect': cdetect,
            'initialized': bool(init),
            'bus_width': width,
            'clock_divider': divider
        }

    # === High-level card operations ===

    def cmd0_go_idle(self):
        """CMD0: Reset card to idle state"""
        status, _ = self.send_command(CMD0_GO_IDLE_STATE, 0, 0)
        return status == 0

    def cmd8_send_if_cond(self, check_pattern=0xAA):
        """CMD8: Send interface condition (voltage check)"""
        # VHS=1 (2.7-3.6V), check pattern
        arg = (1 << 8) | check_pattern
        flags = FLAG_RESPONSE_EXPECT | FLAG_CHECK_CRC
        status, resp = self.send_command(CMD8_SEND_IF_COND, arg, flags)
        if status == 0:
            # Verify echo back
            if (resp[0] & 0xFF) == check_pattern:
                print(f"CMD8 OK: Card supports SD 2.0+, pattern=0x{resp[0]:08X}")
                return True
        print(f"CMD8 failed or not supported: status={status}")
        return False

    def acmd41_send_op_cond(self, hcs=True):
        """ACMD41: Send operating condition"""
        # First send CMD55
        flags = FLAG_RESPONSE_EXPECT | FLAG_CHECK_CRC
        status, _ = self.send_command(CMD55_APP_CMD, 0, flags)
        if status != 0:
            return None

        # Then ACMD41
        arg = 0x40FF8000 if hcs else 0x00FF8000  # HCS + voltage window
        status, resp = self.send_command(ACMD41_SD_SEND_OP_COND, arg, FLAG_RESPONSE_EXPECT)
        if status == 0:
            return resp[0]
        return None

    def cmd2_all_send_cid(self):
        """CMD2: Get Card ID"""
        flags = FLAG_RESPONSE_EXPECT | FLAG_RESPONSE_LONG
        status, resp = self.send_command(CMD2_ALL_SEND_CID, 0, flags)
        if status == 0:
            print(f"CID: {resp[0]:08X} {resp[1]:08X} {resp[2]:08X} {resp[3]:08X}")
            return resp
        return None

    def cmd3_send_relative_addr(self):
        """CMD3: Get relative address"""
        flags = FLAG_RESPONSE_EXPECT | FLAG_CHECK_CRC
        status, resp = self.send_command(CMD3_SEND_RELATIVE_ADDR, 0, flags)
        if status == 0:
            self.rca = (resp[0] >> 16) & 0xFFFF
            print(f"RCA: 0x{self.rca:04X}")
            return self.rca
        return None

    def cmd7_select_card(self):
        """CMD7: Select card"""
        flags = FLAG_RESPONSE_EXPECT | FLAG_CHECK_CRC
        status, resp = self.send_command(CMD7_SELECT_CARD, self.rca << 16, flags)
        return status == 0

    def cmd13_send_status(self):
        """CMD13: Get card status"""
        flags = FLAG_RESPONSE_EXPECT | FLAG_CHECK_CRC
        status, resp = self.send_command(CMD13_SEND_STATUS, self.rca << 16, flags)
        if status == 0:
            return resp[0]
        return None

    def cmd16_set_blocklen(self, blocklen=512):
        """CMD16: Set block length"""
        flags = FLAG_RESPONSE_EXPECT | FLAG_CHECK_CRC
        status, resp = self.send_command(CMD16_SET_BLOCKLEN, blocklen, flags)
        return status == 0

    def acmd6_set_bus_width(self, width=4):
        """ACMD6: Set bus width (1 or 4)"""
        # Send CMD55 first
        flags = FLAG_RESPONSE_EXPECT | FLAG_CHECK_CRC
        status, _ = self.send_command(CMD55_APP_CMD, self.rca << 16, flags)
        if status != 0:
            return False
        # ACMD6: 0=1-bit, 2=4-bit
        arg = 2 if width == 4 else 0
        status, resp = self.send_command(ACMD6_SET_BUS_WIDTH, arg, flags)
        if status == 0:
            self.set_bus_width(width)
            return True
        return False

    def wait_ready(self, timeout_ms=1000):
        """Wait for card to be ready (not busy)"""
        import time
        start = time.time()
        while (time.time() - start) * 1000 < timeout_ms:
            status = self.cmd13_send_status()
            if status is None:
                return False
            # Bits 12:9 = CURRENT_STATE, 8 = READY_FOR_DATA
            state = (status >> 9) & 0xF
            ready = (status >> 8) & 1
            if ready and state == 4:  # 4 = tran (transfer state)
                return True
            time.sleep(0.001)
        return False

    def initialize_card(self):
        """Full card initialization sequence"""
        print("=== SD Card Initialization ===")

        # CMD0 - Reset
        print("CMD0: Go idle...")
        if not self.cmd0_go_idle():
            print("CMD0 failed")
            return False

        # CMD8 - Check voltage
        print("CMD8: Send IF cond...")
        sd_v2 = self.cmd8_send_if_cond()

        # ACMD41 - Wait for card ready
        print("ACMD41: Send OP cond...")
        import time
        for i in range(100):
            ocr = self.acmd41_send_op_cond(hcs=sd_v2)
            if ocr is None:
                print("ACMD41 failed")
                return False
            if ocr & 0x80000000:  # Card ready
                print(f"Card ready! OCR=0x{ocr:08X}")
                break
            time.sleep(0.01)  # 10ms delay between retries
        else:
            print("Card not ready after 100 attempts")
            return False

        # CMD2 - Get CID
        print("CMD2: Get CID...")
        if not self.cmd2_all_send_cid():
            print("CMD2 failed")
            return False

        # CMD3 - Get RCA
        print("CMD3: Get RCA...")
        if not self.cmd3_send_relative_addr():
            print("CMD3 failed")
            return False

        # CMD7 - Select card
        print("CMD7: Select card...")
        if not self.cmd7_select_card():
            print("CMD7 failed")
            return False

        print("=== Card initialized successfully! ===")
        return True

    # === Data transfer operations ===

    def read_block(self, address):
        """Read a 512-byte block from the card (CMD17)"""
        result = self.gf.comms.execute_command(SDIO_CLASS, 0x5, '<I', '<i512s', address)
        status = result[0]
        if status != 0:
            raise RuntimeError(f"read_block failed: {status}")
        return result[1]

    def write_block(self, address, data):
        """Write a 512-byte block to the card (CMD24)"""
        if len(data) != 512:
            raise ValueError("Data must be exactly 512 bytes")
        result = self.gf.comms.execute_command(SDIO_CLASS, 0x6, '<II512s', '<i',
                                               address, 512, data)
        status = result[0] if isinstance(result, tuple) else result
        if status != 0:
            raise RuntimeError(f"write_block failed: {status}")

    def cmd56_read(self, argument, length=512):
        """Send CMD56 and read data from card"""
        if length > 512:
            raise ValueError("Length must be <= 512")
        fmt = f'<iI{length}s'
        result = self.gf.comms.execute_command(SDIO_CLASS, 0x7, '<II', fmt,
                                               argument, length)
        status, response, data = result
        if status != 0:
            raise RuntimeError(f"cmd56_read failed: {status}")
        return response, data

    def cmd56_write(self, argument, data):
        """Send CMD56 with data to card"""
        length = len(data)
        if length > 512:
            raise ValueError("Data must be <= 512 bytes")
        fmt = f'<II{length}s'
        result = self.gf.comms.execute_command(SDIO_CLASS, 0x8, fmt, '<iI',
                                               argument, length, data)
        status, response = result
        if status != 0:
            raise RuntimeError(f"cmd56_write failed: {status}")
        return response

    # === Trigger System ===

    def trigger_config(self, cmd=0xFFFFFFFF, addr=0xFFFFFFFF, ins=0xFFFFFFFF):
        """
        Configure trigger conditions. Use 0xFFFFFFFF to disable a condition.

        Args:
            cmd: SD command index to match (e.g., 24 for CMD24/write)
            addr: Block address to match (e.g., 0x350580 for FSI data sector)
            ins: APDU INS byte to match (e.g., 0x30 for VERIFY)
        """
        result = self.gf.comms.execute_command(SDIO_CLASS, 0x9, '<III', '<i',
                                               cmd, addr, ins)
        status = result[0] if isinstance(result, tuple) else result
        if status != 0:
            raise RuntimeError(f"trigger_config failed: {status}")

    def trigger_arm(self):
        """Arm the trigger. Fires once on match, then auto-disarms."""
        result = self.gf.comms.execute_command(SDIO_CLASS, 0xA, '', '<i')
        status = result[0] if isinstance(result, tuple) else result
        if status != 0:
            raise RuntimeError(f"trigger_arm failed: {status}")

    def trigger_status(self):
        """Get trigger status."""
        result = self.gf.comms.execute_command(SDIO_CLASS, 0xB, '', '<BBIII')
        armed, fired, cmd, addr, ins = result
        return {
            'armed': bool(armed),
            'fired': bool(fired),
            'cmd_match': cmd,
            'addr_match': addr,
            'ins_match': ins
        }

    # === Power Control (TPS7A2033 LDO via J1_P18) ===

    def power_on(self):
        """Enable DUT power (set TPS7A2033 EN high)"""
        result = self.gf.comms.execute_command(SDIO_CLASS, 0xC, '<B', '<i', 1)
        status = result[0] if isinstance(result, tuple) else result
        if status != 0:
            raise RuntimeError(f"power_on failed: {status}")

    def power_off(self):
        """Disable DUT power (set TPS7A2033 EN low)"""
        result = self.gf.comms.execute_command(SDIO_CLASS, 0xC, '<B', '<i', 0)
        status = result[0] if isinstance(result, tuple) else result
        if status != 0:
            raise RuntimeError(f"power_off failed: {status}")

    def power_cycle(self, off_time_ms=100):
        """Power cycle the DUT with specified off time"""
        import time
        self.power_off()
        time.sleep(off_time_ms / 1000.0)
        self.power_on()

    def power_status(self):
        """Get current power state (True=on, False=off)"""
        result = self.gf.comms.execute_command(SDIO_CLASS, 0xD, '', '<B')
        return bool(result[0] if isinstance(result, tuple) else result)

    # === Cycle Counter ===

    def get_cycle_count(self):
        """
        Get current absolute DWT cycle counter.
        At 204 MHz, each cycle = ~4.9 ns.

        Returns:
            Absolute cycle count (uint32, wraps at ~21 seconds)
        """
        result = self.gf.comms.execute_command(SDIO_CLASS, 0xE, '', '<I')
        return result[0] if isinstance(result, tuple) else result

    def get_last_cycles(self):
        """
        Get absolute timestamps of last write and read operations.
        At 204 MHz, each cycle = ~4.9 ns.

        Returns:
            (write_start, write_end, read_start, read_end) tuple
        """
        result = self.gf.comms.execute_command(SDIO_CLASS, 0xF, '', '<IIII')
        return result[0], result[1], result[2], result[3]