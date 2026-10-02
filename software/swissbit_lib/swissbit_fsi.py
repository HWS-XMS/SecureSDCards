#!/usr/bin/env python3
"""
Swissbit FSI protocol - GreatFET implementation

The card requires FAT allocation before accepting FSI commands.
Sequence:
1. Allocate cluster in FAT1 and FAT2
2. Write FSI command to cluster's data sector
3. Read response from same sector
4. Free cluster in FAT1 and FAT2
"""

import gc
import hashlib
import sys
import time
from enum import IntEnum
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "greatfet"))
from sdio_host import SDIOHost

class CardState(IntEnum):
    NOT_ACTIVATED   = 0x0
    UNLOCKED        = 0x1
    LOCKED          = 0x2

SW_SUCCESS          = 0x9000

# Card-specific FAT layout (from capture analysis)
FAT1_SECTOR         = 0x234C      # FAT1 sector containing our cluster entry
FAT2_SECTOR         = 0x3279      # FAT2 sector (same offset)
FAT_ENTRY_OFFSET    = 96     # Byte offset for cluster 54040 (entry 24 * 4)
DATA_SECTOR         = 0x350580    # Cluster 54040 data sector

IDENTIFIER = bytes([
    0x10, 0x6a, 0xf8, 0x1a, 0xd6, 0xf8, 0xc8, 0x70,
    0xac, 0x7e, 0x85, 0xf0, 0xe9, 0x9e, 0xf3, 0x9d,
    0x1e, 0x11, 0xa1, 0xba, 0x87, 0x4a, 0xc6, 0xdb,
    0x42, 0x81, 0x15, 0x8e, 0xfe, 0x6d, 0x3c, 0x81
])

# APDU constants
CLA                 = 0xFF
INS_ACTIVATE        = 0x10
INS_DEACTIVATE      = 0x20
INS_VERIFY          = 0x30
INS_LOCK            = 0x31
INS_CHANGE_PASSWORD = 0x40
INS_CLEAR_PROFILES  = 0x53
INS_FACTORY_RESET   = 0x60
INS_GET             = 0x70

# GET subcommands (P1)
GET_STATUS          = 0x00
GET_CARD_ID         = 0x01
GET_APP_VERSION     = 0x02
GET_CHALLENGE       = 0x05
GET_CONTROLLER_ID   = 0x06

class SwissbitFSI(object):
    def __init__(self, pin):
        self.sdio           = None
        self.fat_block      = None
        self._clock_divider = 10
        self._pin           = pin
        # First-time setup (no recovery)
        self.sdio = SDIOHost()
        self.sdio.init(clock_divider=self._clock_divider)
        if not self.sdio.initialize_card():
            raise RuntimeError("SD card initialization failed")
        self.sdio.cmd16_set_blocklen(512)
        time.sleep(0.2)
        self.fat_block = bytearray(self.sdio.read_block(FAT1_SECTOR))
        self.login(pin)
        self.lock_card()

    @property
    def clock_divider(self):
        return self._clock_divider

    @clock_divider.setter
    def clock_divider(self, value):
        self._clock_divider = value
        if self.sdio:
            self.sdio.set_clock(value)

    def initialize(self, pin, scope):
        """Recovery: reset GreatFET and reinitialize. Retries until success."""
        while True:
            # Reset GreatFET to clear SDIO state
            if self.sdio:
                try:
                    self.sdio.gf.reset()
                except:
                    pass
                self.sdio = None
                gc.collect()
            # Disable glitch MOSFETs, then restore power
            scope.io.glitch_hp  = False
            scope.io.glitch_lp  = False
            scope.io.target_pwr = True
            scope.io.glitch_hp  = True
            scope.io.glitch_lp  = True
            # Reinitialize
            try:
                self.sdio = SDIOHost()
                self.sdio.init(clock_divider=self._clock_divider)
                if self.sdio.initialize_card():
                    self.sdio.cmd16_set_blocklen(512)
                    time.sleep(0.2)
                    self.fat_block = bytearray(self.sdio.read_block(FAT1_SECTOR))
                    self.login(pin)
                    self.lock_card()
                    return
                # Card init failed - reset before retry
                self.sdio.gf.reset()
                self.sdio = None
                gc.collect()
                time.sleep(1.0)
            except:
                if self.sdio:
                    try:
                        self.sdio.gf.reset()
                    except:
                        pass
                    self.sdio = None
                    gc.collect()
                    time.sleep(1.0)

    def soft_reset(self, power_cycle=False):
        """Soft reset: reset GreatFET and reinitialize. Returns True on success."""
        try:
            if power_cycle:
                self.sdio.power_cycle(off_time_ms=200)
                time.sleep(0.3)
            self.sdio.gf.reset()
            time.sleep(0.5)
            self.sdio.init(clock_divider=self._clock_divider)
            if self.sdio.initialize_card():
                self.sdio.cmd16_set_blocklen(512)
                time.sleep(0.2)
                self.fat_block = bytearray(self.sdio.read_block(FAT1_SECTOR))
                self.login(self._pin)
                self.lock_card()
                return True
        except KeyboardInterrupt:
            raise
        except Exception:
            pass
        return False

    def hard_reset(self, psu):
        """Hard reset: power cycle the card via PSU."""
        psu.output = False
        time.sleep(0.5)
        psu.output = True
        time.sleep(2.0)
        return self.soft_reset()

    def send_fsi(self, apdu):
        """Send FSI command and return response"""
        # Build command block
        cmd_block                       = bytearray(512)
        cmd_block[0:32]                 = IDENTIFIER
        cmd_block[0x20]                 = 0x01      # direction
        cmd_block[0x21]                 = 0x00      # flags
        # Length is BIG-ENDIAN in command block!
        cmd_block[0x22]                 = (len(apdu) >> 8) & 0xFF
        cmd_block[0x23]                 = len(apdu) & 0xFF
        cmd_block[0x24:0x24+len(apdu)]  = apdu

        # 1. Allocate cluster in FAT
        self.fat_block[FAT_ENTRY_OFFSET:FAT_ENTRY_OFFSET+4] = b'\xFF\xFF\xFF\x0F'
        self.sdio.write_block(FAT1_SECTOR, bytes(self.fat_block))
        self.sdio.write_block(FAT2_SECTOR, bytes(self.fat_block))

        _sca_verify = len(apdu) > 1 and apdu[1] == INS_VERIFY   # TEMP (SCA)
        if _sca_verify:
            time.sleep(1)   # TEMP (SCA): isolate the verify write from the FAT alloc

        # 2. Write FSI command
        self.sdio.write_block(DATA_SECTOR, bytes(cmd_block))

        if _sca_verify:
            time.sleep(1)   # TEMP (SCA): isolate the compare from the response read

        # 3. Read response
        response = self.sdio.read_block(DATA_SECTOR)

        # 4. Free cluster in FAT
        self.fat_block[FAT_ENTRY_OFFSET:FAT_ENTRY_OFFSET+4] = b'\x00\x00\x00\x00'
        self.sdio.write_block(FAT1_SECTOR, bytes(self.fat_block))
        self.sdio.write_block(FAT2_SECTOR, bytes(self.fat_block))

        return self._parse_response(response)

    def _parse_response(self, data):
        length      = (data[2] << 8) | data[3]  # big-endian
        if length > 0 and length <= 500:
            payload = data[4:4+length]
            if length >= 2:
                sw  = (payload[-2] << 8) | payload[-1]
                return sw, payload[:-2] if length > 2 else b''
        return None, None

    @property
    def status(self) -> dict:
        apdu = bytes([CLA, INS_GET, GET_STATUS, 0x00, 0x00])
        sw, data = self.send_fsi(apdu)
        if sw == SW_SUCCESS and data:
            return self._parse_status(data)
        return None

    def _parse_status(self, data):
        if len(data) < 15:
            return None
        return {
            'license_mode':         data[0],
            'system_status':        data[1],
            'user_pw_retries':      data[2],
            'so_pw_retries':        data[3],
            'num_resets':          (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7],
            'security_flags':       data[8],
            'reserved':             data[9],
            'partition_offset':    (data[10] << 24) | (data[11] << 16) | (data[12] << 8) | data[13],
            'app_version':          data[14] if len(data) > 14 else 0,
        }

    @property
    def card_id(self):
        apdu = bytes([CLA, INS_GET, GET_CARD_ID, 0x00, 0x00])
        sw, data = self.send_fsi(apdu)
        return data if sw == SW_SUCCESS else None

    @property
    def app_version(self):
        apdu = bytes([CLA, INS_GET, GET_APP_VERSION, 0x00, 0x00])
        sw, data = self.send_fsi(apdu)
        return data if sw == SW_SUCCESS else None

    @property
    def challenge(self):
        apdu = bytes([CLA, INS_GET, GET_CHALLENGE, 0x00, 0x00])
        sw, data = self.send_fsi(apdu)
        return data if sw == SW_SUCCESS else None

    @property
    def controller_id(self):
        apdu = bytes([CLA, INS_GET, GET_CONTROLLER_ID, 0x00, 0x00])
        sw, data = self.send_fsi(apdu)
        return data if sw == SW_SUCCESS else None

    def activate(self):
        """Activate card protection (requires prior VERIFY)"""
        apdu = bytes([CLA, INS_ACTIVATE, 0x00, 0x00, 0x00])
        return self.send_fsi(apdu)

    def deactivate(self, sopin):
        """Deactivate card protection using SO PIN with challenge-response auth"""
        challenge = self.challenge
        if not challenge:
            return None, None
        sopin_hash = hashlib.sha256(sopin).digest()
        response = hashlib.sha256(sopin_hash + challenge).digest()
        data = bytes([len(response)]) + response
        apdu = bytes([CLA, INS_DEACTIVATE, 0x00, 0x00, len(data)]) + data
        return self.send_fsi(apdu)

    def verify(self, response_data, is_so=False):
        """Verify with challenge-response. response_data should be 32 bytes."""
        p1 = 0x01 if is_so else 0x00
        # Format: length byte (0x20=32) + 32-byte response
        data = bytes([len(response_data)]) + response_data
        apdu = bytes([CLA, INS_VERIFY, p1, 0x00, len(data)]) + data
        return self.send_fsi(apdu)

    def arm_trigger_on_verify(self):
        """Arm trigger to fire on next VERIFY command"""
        self.sdio.trigger_config(cmd=24, addr=DATA_SECTOR, ins=INS_VERIFY)
        self.sdio.trigger_arm()

    def arm_trigger_on_status(self):
        """Arm trigger to fire on next GET_STATUS command"""
        self.sdio.trigger_config(cmd=24, addr=DATA_SECTOR, ins=INS_GET)
        self.sdio.trigger_arm()

    @property
    def trigger_status(self):
        return self.sdio.trigger_status()

    def login(self, pin, is_so=False):
        """Full login sequence: get challenge, compute response, verify"""
        challenge = self.challenge
        if not challenge:
            return None, None
        pin_hash = hashlib.sha256(pin).digest()
        response = hashlib.sha256(pin_hash + challenge).digest()
        return self.verify(response, is_so)

    def lock_card(self):
        apdu = bytes([CLA, INS_LOCK, 0x00, 0x00, 0x00])
        return self.send_fsi(apdu)

    def change_password(self, old_response, new_pin, is_so=False):
        """Change password. old_response is 32-byte challenge-response, new_pin is plaintext."""
        p1 = 0x01 if is_so else 0x00
        # Format: outer_len + old_len + old_response + new_len + new_pin
        inner_data = bytes([len(old_response)]) + old_response + bytes([len(new_pin)]) + new_pin
        data = bytes([len(inner_data)]) + inner_data
        apdu = bytes([CLA, INS_CHANGE_PASSWORD, p1, 0x00, len(data)]) + data
        return self.send_fsi(apdu)

    def factory_reset(self, sopin):
        """Factory reset - WIPES ALL DATA using raw SO PIN"""
        data = bytes([len(sopin)]) + sopin
        apdu = bytes([CLA, INS_FACTORY_RESET, 0x00, 0x01, len(data)]) + data
        return self.send_fsi(apdu)
