"""
Python wrapper for Swissbit libCardManagement.so
FULLY VERIFIED through reverse engineering + UBOOT source code cross-reference

All function signatures verified via assembly analysis of cardManagerCLI binary
All struct definitions extracted from UBOOT source code (dp.c)

WARNING: Incorrect usage could permanently brick hardware!
"""
import ctypes
from enum import IntEnum
import logging
from datetime import datetime
import os

# Setup credential logging
CREDENTIAL_LOG = 'swissbit_credentials.log'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler(CREDENTIAL_LOG),
        logging.StreamHandler()
    ]
)


# ============================================================================
# APDU COMMAND MAP (reverse engineered from libCardManagement.so)
# ============================================================================
# All commands use CLA=0xFF
#
# INS  | Functions
# -----|----------
# 0x10 | activate (both variants)
# 0x20 | deactivate
# 0x30 | verify (PIN)
# 0x31 | lockCard
# 0x40 | changePassword
# 0x50 | unblockPassword, setCdromArea, setReadException, setCdromAreaAndReadException
# 0x53 | reset, clearProtectionProfiles, setCdromAreaBackToDefault
# 0x70 | GET (P1 selects function):
#      |   P1=0x00: getStatus (cardStatus)
#      |   P1=0x01: getId
#      |   P1=0x02: getAppVersion / getBaseFWVersion
#      |   P1=0x03: getStatus (cardStatusNvram)
#      |   P1=0x04: getStatus (cardStatusException)
#      |   P1=0x05: getChallenge
#      |   P1=0x06: getControllerId
#      |   P1=0x07: getProtectionProfiles
#      |   P1=0x08: getPartition / getOverallSizeSD
#      |   P1=0x09: getOverallSizeUSB
# 0x80 | SET/CONFIG: configureNVRAM, setExtendedSecurityFlags, setSecureActivationKey,
#      |             setAuthenticityCheckSecret, customizeCard
# 0xD0 | getId
# 0xD1 | readNVRAM, writeNVRAM
# 0xF0 | setLicenseMode
# 0xF1 | challengeFirmware (PUF query)
# 0xF2 | checkAuthenticity
#
# Note: 0x70, 0x50, 0x53, 0x80 are multi-purpose - P1/P2 selects specific function

# ============================================================================
# CONSTANTS from UBOOT dp.c and reverse engineering
# ============================================================================

# Password/PIN constraints
DP_PASSWORD_MAX_LENGTH = 32
DP_CHALLENGE_LENGTH = 32
DP_HASH_LENGTH = 32
DP_ID_LENGTH = 16

# Return codes
# IMPORTANT: Two different success indicators:
# 1. Function return value: 0 = success, negative = error (e.g., -3)
# 2. Status field in structs: 0x9000 = success (inside StatusResponse/StatusNvramResponse)
FUNCTION_SUCCESS = 0       # Function returns 0 for success
SW_SUCCESS = 0x9000        # Status field in response structs = 0x9000 for success

# Card States (from UBOOT dp.c:2898-2909)
class CardState(IntEnum):
    NOT_ACTIVATED = 0x0  # Card has not been activated yet
    UNLOCKED = 0x1       # Card is activated and unlocked
    LOCKED = 0x2         # Card is activated but locked


# Extended Security Flags (from reverse engineering cardManagerCLI)
# These flags are stored in StatusResponse.flags field
#
# Bit 0x10 (bit 4): HASH_AUTH_REQUIRED
#   When set: Card requires challenge-response hashed authentication
#             CLI auto-fetches challenge via getHashChallenge() and computes:
#             hash = sha256(sha256(PIN) + challenge)
#             Then sends hash to verify() instead of plain PIN
#   When clear: Plain PIN authentication works directly
#
# Evidence: cardManagerCLI:407981 - "test BYTE PTR [rsp+0x1c],0x10"
#           followed by conditional call to getHashChallenge and calc_sha_256
#
# Default flags on our card: 0x33 (bits 0,1,4,5 set) - hash auth required
# To enable plain PIN: clear bit 0x10, e.g., 0x33 -> 0x23
class ExtendedSecurityFlags(IntEnum):
    HASH_AUTH_REQUIRED = 0x10  # Bit 4: requires challenge-response hash auth


# ============================================================================
# STRUCTURES from UBOOT dp.c
# ============================================================================

class StatusResponse(ctypes.Structure):
    """Card status response structure

    Source: UBOOT dp.c lines 63-73
    typedef struct _STATUS_RESPONSE {
        uint8_t mode;
        uint8_t state;
        int8_t counter;
        int8_t so_counter;
        uint32_t reset_counter;
        uint8_t rfu[2];
        uint32_t cdrom;
        uint8_t flags;
        uint16_t status;
    } __attribute__((packed)) STATUS_RESPONSE;
    """
    _pack_ = 1
    _fields_ = [
        ("mode", ctypes.c_uint8),           # Operating mode
        ("state", ctypes.c_uint8),          # Card state: 0=not activated, 1=unlocked, 2=locked
        ("counter", ctypes.c_int8),         # Password retry counter (remaining attempts)
        ("so_counter", ctypes.c_int8),      # SO/Admin password retry counter
        ("reset_counter", ctypes.c_uint32), # Number of resets performed
        ("rfu", ctypes.c_uint8 * 2),        # Reserved for future use
        ("cdrom", ctypes.c_uint32),         # CD-ROM protection address
        ("flags", ctypes.c_uint8),          # Extended security flags
        ("status", ctypes.c_uint16),        # Status code (0x9000 = success)
    ]


class StatusNvramResponse(ctypes.Structure):
    """NVRAM status response structure

    Source: UBOOT dp.c lines 75-84
    typedef struct _STATUS_NVRAMRESPONSE {
        uint32_t hiddenSectors;
        uint8_t accessRandomRights;
        uint8_t accessCyclicRights;
        uint32_t randomSectors;
        uint32_t cyclicSectors;
        uint32_t nextSector;
        uint8_t wrap;
        uint16_t status;
    } __attribute__((packed)) STATUS_NVRAMRESPONSE;
    """
    _pack_ = 1
    _fields_ = [
        ("hidden_sectors", ctypes.c_uint32),      # Number of hidden sectors
        ("access_random_rights", ctypes.c_uint8), # Access rights for random NVRAM
        ("access_cyclic_rights", ctypes.c_uint8), # Access rights for cyclic NVRAM
        ("random_sectors", ctypes.c_uint32),      # Number of random access sectors
        ("cyclic_sectors", ctypes.c_uint32),      # Number of cyclic access sectors
        ("next_sector", ctypes.c_uint32),         # Next sector to be written (cyclic)
        ("wrap", ctypes.c_uint8),                 # Wrap-around flag for cyclic buffer
        ("status", ctypes.c_uint16),              # Status code (0x9000 = success)
    ]


class ProtectionProfile(ctypes.Structure):
    """Protection profile structure for card access control

    Evidence: Mangled name _ZN3sfc21setProtectionProfilesEP8SFC_FSI_PK17ProtectionProfilej
    Based on cardManagerCLI usage and typical protection profile implementations
    """
    _fields_ = [
        ("start_address", ctypes.c_uint),  # Starting LBA/sector for this protection zone
        ("profile_type", ctypes.c_ubyte),  # Protection type (see ProtectionType enum)
    ]


class ProtectionType(IntEnum):
    """Protection profile types (from cardManagerCLI --help)"""
    PRIVATE_RW = 0      # Private read-write area
    PUBLIC_RW = 1       # Public read-write area
    PRIVATE_CDROM = 2   # Private CD-ROM (read-only for user)
    PUBLIC_CDROM = 3    # Public CD-ROM (read-only)
    PRIVATE_RO = 4      # Private read-only
    PUBLIC_RO = 5       # Public read-only
    FLEXIBLE_RO = 6     # Flexible read-only


# ============================================================================
# MAIN WRAPPER CLASS
# ============================================================================

class CardManagement(object):
    """Wrapper for Swissbit libCardManagement.so

    All function signatures verified through:
    1. Disassembly of cardManagerCLI binary (x86-64 calling convention)
    2. Cross-reference with UBOOT source code structure definitions
    """

    def __init__(self, lib_path: str):
        assert lib_path is not None, "Path to SwissBit .so is empty!"
        self.__lib = ctypes.CDLL(lib_path)
        self._setup_functions()

    def _setup_functions(self):
        """Configure ctypes function signatures - ALL VERIFIED via assembly analysis"""

        # VERIFIED: Assembly at 4054b7-4054d6 shows 6 parameters in rdi,rsi,rdx,rcx,r8,r9
        self.__lib.activate.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint,
                                         ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint, ctypes.c_uint]
        self.__lib.activate.restype = ctypes.c_int

        # VERIFIED: Assembly at 405197-40519e shows ONLY 2 parameters in rdi,rsi
        # CRITICAL: NO length parameter - fixed 32-byte key expected!
        self.__lib.activateSecure.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_ubyte)]
        self.__lib.activateSecure.restype = ctypes.c_int

        # VERIFIED: Assembly at 4050dd shows 3 parameters in rdi,rsi,rdx
        self.__lib.deactivate.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint]
        self.__lib.deactivate.restype = ctypes.c_int

        # VERIFIED: Assembly at 404f44-404f77 shows 8 parameters
        # Wrapper function unpacking cardStatus struct into individual pointers
        self.__lib.getStatus.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint),
                                          ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint),
                                          ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint),
                                          ctypes.POINTER(ctypes.c_uint)]
        self.__lib.getStatus.restype = ctypes.c_int

        # VERIFIED: Assembly at 404e48 shows 6 parameters
        self.__lib.getStatusNvram.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint),
                                               ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint),
                                               ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint)]
        self.__lib.getStatusNvram.restype = ctypes.c_int

        # VERIFIED: Assembly at 4061fc-40620a shows 2 parameters
        self.__lib.getCardId.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_ubyte)]
        self.__lib.getCardId.restype = ctypes.c_int

        # VERIFIED: Assembly at 40681c shows 3 parameters
        self.__lib.getControllerId.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_ubyte),
                                                ctypes.POINTER(ctypes.c_size_t)]
        self.__lib.getControllerId.restype = ctypes.c_int

        # VERIFIED: Assembly at 404557-40455f shows 3 parameters
        self.__lib.verify.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint]
        self.__lib.verify.restype = ctypes.c_int

        # VERIFIED: Assembly at 405bb5 shows 1 parameter
        self.__lib.lockCard.argtypes = [ctypes.c_char_p]
        self.__lib.lockCard.restype = ctypes.c_int

        # VERIFIED: Assembly at 4046da shows 5 parameters
        self.__lib.changePassword.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint,
                                               ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint]
        self.__lib.changePassword.restype = ctypes.c_int

        # VERIFIED: Assembly at 4043cd shows 5 parameters
        self.__lib.unblockPassword.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint,
                                                ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint]
        self.__lib.unblockPassword.restype = ctypes.c_int

        # VERIFIED: Assembly at 4042cd shows 3 parameters
        self.__lib.reset.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint]
        self.__lib.reset.restype = ctypes.c_int

        # VERIFIED: Library function at 6f20, same pattern as reset
        self.__lib.resetAndFormat.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint]
        self.__lib.resetAndFormat.restype = ctypes.c_int

        # VERIFIED: Assembly at 4053a4-4053b7 shows 5 parameters
        self.__lib.readNvram.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_ubyte),
                                          ctypes.POINTER(ctypes.c_uint), ctypes.c_int, ctypes.c_uint]
        self.__lib.readNvram.restype = ctypes.c_int

        # VERIFIED: Assembly at 404187-40419c shows 6 parameters
        self.__lib.writeNvram.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint,
                                           ctypes.c_int, ctypes.c_int, ctypes.c_uint]
        self.__lib.writeNvram.restype = ctypes.c_int

        # VERIFIED: Assembly at 40499d shows 6 parameters
        self.__lib.configureNvram.argtypes = [ctypes.c_char_p, ctypes.c_uint, ctypes.c_uint,
                                               ctypes.c_uint, ctypes.c_uint, ctypes.c_ubyte]
        self.__lib.configureNvram.restype = ctypes.c_int

        # VERIFIED: Assembly at 404bf2-404bfb shows 4 parameters
        self.__lib.getProtectionProfiles.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint),
                                                      ctypes.POINTER(ProtectionProfile), ctypes.c_uint]
        self.__lib.getProtectionProfiles.restype = ctypes.c_int

        # VERIFIED: Assembly at 4066ec-4066f2 shows 3 parameters
        self.__lib.setProtectionProfiles.argtypes = [ctypes.c_char_p, ctypes.POINTER(ProtectionProfile),
                                                      ctypes.c_uint]
        self.__lib.setProtectionProfiles.restype = ctypes.c_int

        # VERIFIED: Assembly at 404a5e shows 1 parameter
        self.__lib.clearProtectionProfiles.argtypes = [ctypes.c_char_p]
        self.__lib.clearProtectionProfiles.restype = ctypes.c_int

        # VERIFIED: nm shows lockCard at 0x6a00
        self.__lib.lockCard.argtypes = [ctypes.c_char_p]
        self.__lib.lockCard.restype = ctypes.c_int

        # VERIFIED: nm shows getLoginChallenge at 0x5c90
        self.__lib.getLoginChallenge.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_ubyte)]
        self.__lib.getLoginChallenge.restype = ctypes.c_int

        # VERIFIED: Disassembly at libCardManagement.so:c1c0-c2da
        # Sends APDU: FF F1 <mode> 00 20 <32 bytes>, receives 32 bytes back
        self.__lib.challengeFirmware.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_ubyte),
                                                  ctypes.POINTER(ctypes.c_ubyte), ctypes.c_ubyte]
        self.__lib.challengeFirmware.restype = ctypes.c_int

        # VERIFIED: Disassembly at libCardManagement.so:5e70
        # Returns application version as uint32
        self.__lib.getApplicationVersion.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint)]
        self.__lib.getApplicationVersion.restype = ctypes.c_int

        # VERIFIED: Disassembly at libCardManagement.so:5f60
        # Returns two version strings (major, minor)
        self.__lib.getBaseFWVersion.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        self.__lib.getBaseFWVersion.restype = ctypes.c_int

        # VERIFIED: Disassembly at libCardManagement.so:6190
        # Tries USB first, then SD. Returns size as uint32
        self.__lib.getOverallSize.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint)]
        self.__lib.getOverallSize.restype = ctypes.c_int

        # VERIFIED: Disassembly at libCardManagement.so:6060
        # Returns 8 uint32 values: 4 partitions x (offset, size)
        self.__lib.getPartitionTable.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint)]
        self.__lib.getPartitionTable.restype = ctypes.c_int

        # VERIFIED: Mangled as _Z11getDiskSizePKc, uses ioctl internally
        # Returns disk size as uint64
        self.__lib._Z11getDiskSizePKc.argtypes = [ctypes.c_char_p]
        self.__lib._Z11getDiskSizePKc.restype = ctypes.c_uint64

        # Low-level APDU transmission functions (for fuzzing/research)
        # sfc::open - opens device, returns handle
        self.__lib._ZN3sfc4openEPKcPP8SFC_FSI_.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
        self.__lib._ZN3sfc4openEPKcPP8SFC_FSI_.restype = ctypes.c_int

        # fsi_transmit_se - send APDU, get response
        self.__lib.fsi_transmit_se.argtypes = [
            ctypes.c_void_p,                    # handle
            ctypes.POINTER(ctypes.c_ubyte),     # command
            ctypes.c_uint,                      # command_len
            ctypes.POINTER(ctypes.c_ubyte),     # response
            ctypes.POINTER(ctypes.c_uint),      # response_len
        ]
        self.__lib.fsi_transmit_se.restype = ctypes.c_int

        # sfc::close - close device handle
        self.__lib._ZN3sfc5closeEP8SFC_FSI_.argtypes = [ctypes.c_void_p]
        self.__lib._ZN3sfc5closeEP8SFC_FSI_.restype = ctypes.c_int

        # fsi_open - open FSI communication file
        self.__lib.fsi_open.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
        self.__lib.fsi_open.restype = ctypes.c_int

        # fsi_close - close FSI handle
        self.__lib.fsi_close.argtypes = [ctypes.c_void_p]
        self.__lib.fsi_close.restype = ctypes.c_int

    @staticmethod
    def _bytes_to_array(data: bytes) -> ctypes.Array:
        """Convert bytes to ctypes array"""
        assert data is not None, "Data is None!"
        return (ctypes.c_ubyte * len(data)).from_buffer_copy(data)

    @staticmethod
    def is_success(return_code: int) -> bool:
        """Check if function return code indicates success

        IMPORTANT: Function returns 0 for success, negative for errors
        This is NOT the same as the 0x9000 status code in response structs!

        Returns:
            True if return_code == 0 (success)
            False if return_code < 0 (error)
        """
        return return_code == FUNCTION_SUCCESS  # Check for 0, not 0x9000!

    def activate(self, card_path: str, user_pin: bytes, admin_pin: bytes, retries: int = 10) -> int:
        """Activate card protection

        Args:
            card_path: Device path (e.g., "/dev/sdb")
            user_pin: User PIN (max 32 bytes, from UBOOT DP_PASSWORD_MAX_LENGTH)
            admin_pin: Admin/SO PIN (max 32 bytes)
            retries: Retry counter (3-15, default 10 from CLI hardcode at 4054b7)

        Returns:
            int: 0 = success, negative = error (e.g., -3 = can't open device)

        Assembly verification: cardManagerCLI:4054b7-4054d6
        """
        assert len(user_pin) <= DP_PASSWORD_MAX_LENGTH, f"User PIN too long (max {DP_PASSWORD_MAX_LENGTH})"
        assert len(admin_pin) <= DP_PASSWORD_MAX_LENGTH, f"Admin PIN too long (max {DP_PASSWORD_MAX_LENGTH})"
        assert 3 <= retries <= 15, "Retry counter must be 3-15 (from UBOOT dp.c:1601-1602)"

        logging.info(f"ACTIVATE - Device: {card_path}, PIN: {user_pin.decode()}, SO-PIN: {admin_pin.decode()}, Retries: {retries}")
        user_pin_arr = self._bytes_to_array(user_pin)
        admin_pin_arr = self._bytes_to_array(admin_pin)
        result = self.__lib.activate(
            card_path.encode('utf-8'),
            user_pin_arr, len(user_pin),
            admin_pin_arr, len(admin_pin),
            retries
        )
        logging.info(f"ACTIVATE - Result: {result} ({'SUCCESS' if result == 0 else 'FAILED'})")
        return result

    def activate_secure(self, card_path: str, key_32bytes: bytes) -> int:
        """Activate card with secure 32-byte key

        Args:
            card_path: Device path
            key_32bytes: EXACTLY 32-byte activation key (NO LENGTH PARAM IN SIGNATURE!)

        Returns:
            int: 0 = success, negative = error

        CRITICAL: Key must be EXACTLY 32 bytes!
        Assembly verification: cardManagerCLI:405197-40519e (only rdi,rsi used)
        """
        assert len(key_32bytes) == 32, "Secure activation key must be EXACTLY 32 bytes!"
        key_arr = self._bytes_to_array(key_32bytes)
        return self.__lib.activateSecure(card_path.encode('utf-8'), key_arr)

    def deactivate(self, card_path: str, admin_pin: bytes) -> int:
        """Deactivate card protection

        Args:
            card_path: Device path
            admin_pin: Admin/SO PIN

        Returns:
            int: 0 = success, negative = error

        Assembly verification: cardManagerCLI:4050dd
        """
        logging.info(f"DEACTIVATE - Device: {card_path}, SO-PIN: {admin_pin.decode()}")
        pin_arr = self._bytes_to_array(admin_pin)
        result = self.__lib.deactivate(card_path.encode('utf-8'), pin_arr, len(admin_pin))
        logging.info(f"DEACTIVATE - Result: {result} ({'SUCCESS' if result == 0 else 'FAILED'})")
        return result

    def deactivate_hashed(self, card_path: str, admin_pin: bytes) -> int:
        """Deactivate card using hashed SO-PIN (for cards with HASHED_AUTH flag)

        Process: hash = sha256(sha256(SO-PIN) + challenge)

        Returns:
            int: 0 = success, negative = error
        """
        import hashlib

        logging.info(f"DEACTIVATE_HASHED - Device: {card_path}, SO-PIN: {admin_pin.decode()}")

        # Get challenge
        ret, challenge = self.get_login_challenge(card_path)
        if not self.is_success(ret):
            logging.info(f"DEACTIVATE_HASHED - Failed to get challenge: {ret}")
            return ret

        # Compute hash = sha256(sha256(SO-PIN) + challenge)
        sopin_hash = hashlib.sha256(admin_pin).digest()
        combined = sopin_hash + challenge
        final_hash = hashlib.sha256(combined).digest()

        # Send hashed SO-PIN
        hash_arr = self._bytes_to_array(final_hash)
        result = self.__lib.deactivate(card_path.encode('utf-8'), hash_arr, len(final_hash))
        logging.info(f"DEACTIVATE_HASHED - Result: {result} ({'SUCCESS' if result == 0 else 'FAILED'})")
        return result

    def get_status(self, card_path: str) -> tuple[int, StatusResponse]:
        """Get card status

        Args:
            card_path: Device path

        Returns:
            Tuple of (status_code, StatusResponse object)
            - status_code: int (0 = success, negative = error)
            - StatusResponse: struct with all card status fields

        Fields in StatusResponse (from UBOOT dp.c:63-73):
            - mode: Operating mode
            - state: 0=not activated, 1=unlocked, 2=locked
            - counter: Password retry attempts remaining
            - so_counter: SO password retry attempts remaining
            - reset_counter: Number of resets
            - cdrom: CD-ROM protection address
            - flags: Extended security flags
            - status: Status word

        Assembly verification: cardManagerCLI:404f44-404f77
        Library unpacking: libCardManagement.so:5970
        """
        p1, p2, p3, p4, p5, p6, p7 = (ctypes.c_uint() for _ in range(7))
        result = self.__lib.getStatus(
            card_path.encode('utf-8'),
            ctypes.byref(p1), ctypes.byref(p2), ctypes.byref(p3), ctypes.byref(p4),
            ctypes.byref(p5), ctypes.byref(p6), ctypes.byref(p7)
        )

        # Create StatusResponse from unpacked values
        # Based on libCardManagement.so:5993-59cf unpacking pattern
        status_resp = StatusResponse(
            mode=p1.value,
            state=p2.value,
            counter=ctypes.c_int8(p3.value).value,
            so_counter=ctypes.c_int8(p4.value).value,
            reset_counter=p5.value,
            cdrom=p6.value,
            flags=p7.value,
            status=result
        )
        return result, status_resp

    def get_status_nvram(self, card_path: str) -> tuple[int, StatusNvramResponse]:
        """Get NVRAM status

        Args:
            card_path: Device path

        Returns:
            Tuple of (status_code, StatusNvramResponse object)
            - status_code: int (0 = success, negative = error)

        Fields from UBOOT dp.c:75-84
        Assembly verification: cardManagerCLI:404e48
        """
        p1, p2, p3, p4, p5 = (ctypes.c_uint() for _ in range(5))
        result = self.__lib.getStatusNvram(
            card_path.encode('utf-8'),
            ctypes.byref(p1), ctypes.byref(p2), ctypes.byref(p3),
            ctypes.byref(p4), ctypes.byref(p5)
        )

        nvram_resp = StatusNvramResponse(
            hidden_sectors=p1.value,
            access_random_rights=p2.value,
            access_cyclic_rights=p3.value,
            random_sectors=p4.value,
            cyclic_sectors=p5.value,
            next_sector=0,  # Not returned by this wrapper
            wrap=0,  # Not returned by this wrapper
            status=result
        )
        return result, nvram_resp

    def get_card_id(self, card_path: str) -> tuple[int, bytes]:
        """Get card ID

        Args:
            card_path: Device path

        Returns:
            Tuple of (status_code, 8-byte card ID)
            - status_code: int (0 = success, negative = error)
            - card_id: bytes (8 bytes)

        From UBOOT: DP_ID_LENGTH = 16, but typically 8 bytes used
        Assembly verification: cardManagerCLI:4061fc-40620a
        """
        card_id = (ctypes.c_ubyte * 16)()
        result = self.__lib.getCardId(card_path.encode('utf-8'), card_id)
        return result, bytes(card_id[:8])

    def get_controller_id(self, card_path: str) -> tuple[int, bytes]:
        """Get controller ID (variable length)

        Returns:
            Tuple of (status_code, controller_id)
            - status_code: int (0 = success, negative = error)
            - controller_id: bytes (variable length)

        Assembly verification: cardManagerCLI:40681c
        """
        buffer = (ctypes.c_ubyte * 256)()
        length = ctypes.c_size_t(256)
        result = self.__lib.getControllerId(card_path.encode('utf-8'), buffer, ctypes.byref(length))
        return result, bytes(buffer[:length.value])

    def verify(self, card_path: str, pin: bytes) -> int:
        """Verify PIN (login)

        Returns:
            int: 0 = success, negative = error

        Assembly verification: cardManagerCLI:404557-40455f
        """
        logging.info(f"VERIFY - Device: {card_path}, PIN: {pin.decode()}")
        pin_arr = self._bytes_to_array(pin)
        result = self.__lib.verify(card_path.encode('utf-8'), pin_arr, len(pin))
        logging.info(f"VERIFY - Result: {result} ({'SUCCESS' if result == 0 else 'FAILED'})")
        return result

    def lock_card(self, card_path: str) -> int:
        """Lock the card (logout)

        Returns:
            int: 0 = success, negative = error

        Assembly verification: cardManagerCLI:405bb5
        """
        logging.info(f"LOCK - Device: {card_path}")
        result = self.__lib.lockCard(card_path.encode('utf-8'))
        logging.info(f"LOCK - Result: {result} ({'SUCCESS' if result == 0 else 'FAILED'})")
        return result

    def get_login_challenge(self, card_path: str) -> tuple[int, bytes]:
        """Get login challenge for hashed PIN verification

        IMPORTANT: The challenge only changes after a SUCCESSFUL verify!
        Calling this multiple times returns the same challenge until
        verify_hashed() succeeds.

        Returns:
            Tuple of (status_code, challenge)
            - status_code: int (0 = success, negative = error)
            - challenge: bytes (32 bytes)

        Library verification: nm shows getLoginChallenge at 0x5c90
        """
        challenge = (ctypes.c_ubyte * 32)()
        result = self.__lib.getLoginChallenge(card_path.encode('utf-8'), challenge)
        return result, bytes(challenge)

    def verify_hashed(self, card_path: str, pin: bytes, challenge: bytes) -> int:
        """Verify PIN using hashed authentication (for cards with HASHED_AUTH flag)

        Process: hash = sha256(sha256(PIN) + challenge)
        Source: UBOOT dp.c:1709-1757

        Args:
            card_path: Device path
            pin: User PIN
            challenge: Challenge bytes (must be pre-fetched with get_login_challenge)

        Returns:
            int: 0 = success, negative = error
        """
        import hashlib

        logging.info(f"VERIFY_HASHED - Device: {card_path}, PIN: {pin.decode()}")

        # Compute hash = sha256(sha256(PIN) + challenge)
        pin_hash = hashlib.sha256(pin).digest()
        combined = pin_hash + challenge
        final_hash = hashlib.sha256(combined).digest()

        # Send hashed PIN
        hash_arr = self._bytes_to_array(final_hash)
        result = self.__lib.verify(card_path.encode('utf-8'), hash_arr, len(final_hash))
        logging.info(f"VERIFY_HASHED - Result: {result} ({'SUCCESS' if result == 0 else 'FAILED'})")
        return result

    def change_password(self, card_path: str, old_pin: bytes, new_pin: bytes) -> int:
        """Change user password

        Returns:
            int: 0 = success, negative = error

        Assembly verification: cardManagerCLI:4046da
        """
        assert len(new_pin) <= DP_PASSWORD_MAX_LENGTH, f"New PIN too long (max {DP_PASSWORD_MAX_LENGTH})"
        old_pin_arr = self._bytes_to_array(old_pin)
        new_pin_arr = self._bytes_to_array(new_pin)
        return self.__lib.changePassword(
            card_path.encode('utf-8'),
            old_pin_arr, len(old_pin),
            new_pin_arr, len(new_pin)
        )

    def unblock_password(self, card_path: str, admin_pin: bytes, new_user_pin: bytes) -> int:
        """Unblock user password using admin PIN

        Returns:
            int: 0 = success, negative = error

        Assembly verification: cardManagerCLI:4043cd
        """
        assert len(new_user_pin) <= DP_PASSWORD_MAX_LENGTH, f"New PIN too long (max {DP_PASSWORD_MAX_LENGTH})"
        logging.info(f"UNBLOCK - Device: {card_path}, SO-PIN: {admin_pin.decode()}, New PIN: {new_user_pin.decode()}")
        admin_arr = self._bytes_to_array(admin_pin)
        new_pin_arr = self._bytes_to_array(new_user_pin)
        result = self.__lib.unblockPassword(
            card_path.encode('utf-8'),
            admin_arr, len(admin_pin),
            new_pin_arr, len(new_user_pin)
        )
        logging.info(f"UNBLOCK - Result: {result} ({'SUCCESS' if result == 0 else 'FAILED'})")
        return result

    def reset(self, card_path: str, admin_pin: bytes) -> int:
        """Reset card (deactivate and wipe)

        Returns:
            int: 0 = success, negative = error

        Assembly verification: cardManagerCLI:4042cd
        """
        logging.info(f"RESET - Device: {card_path}, SO-PIN: {admin_pin.decode()}")
        admin_arr = self._bytes_to_array(admin_pin)
        result = self.__lib.reset(card_path.encode('utf-8'), admin_arr, len(admin_pin))
        logging.info(f"RESET - Result: {result} ({'SUCCESS' if result == 0 else 'FAILED'})")
        return result

    def reset_and_format(self, card_path: str, admin_pin: bytes) -> int:
        """Reset and format card

        Returns:
            int: 0 = success, negative = error

        Library verification: libCardManagement.so:6f20
        """
        admin_arr = self._bytes_to_array(admin_pin)
        return self.__lib.resetAndFormat(card_path.encode('utf-8'), admin_arr, len(admin_pin))

    def read_nvram(self, card_path: str, length: int, is_cyclic: bool, offset: int) -> tuple[int, bytes]:
        """Read from NVRAM

        Args:
            is_cyclic: True for cyclic NVRAM, False for random access
            offset: Sector offset (from UBOOT dp.c:4053a8)

        Returns:
            Tuple of (status_code, data)
            - status_code: int (0 = success, negative = error)
            - data: bytes (actual data read)

        Assembly verification: cardManagerCLI:4053a4-4053b7
        """
        buffer = (ctypes.c_ubyte * length)()
        read_length = ctypes.c_uint(length)
        result = self.__lib.readNvram(
            card_path.encode('utf-8'),
            buffer, ctypes.byref(read_length),
            1 if is_cyclic else 0, offset
        )
        return result, bytes(buffer[:read_length.value])

    def write_nvram(self, card_path: str, data: bytes, is_cyclic: bool, is_append: bool, offset: int) -> int:
        """Write to NVRAM

        Args:
            is_cyclic: True for cyclic NVRAM, False for random
            is_append: True to append (for cyclic), False to overwrite
            offset: Sector offset

        Returns:
            int: 0 = success, negative = error

        Assembly verification: cardManagerCLI:404187-40419c
        """
        data_arr = self._bytes_to_array(data)
        return self.__lib.writeNvram(
            card_path.encode('utf-8'),
            data_arr, len(data),
            1 if is_cyclic else 0,
            1 if is_append else 0,
            offset
        )

    def configure_nvram(self, card_path: str, param1: int, param2: int, param3: int,
                       param4: int, param5: int) -> int:
        """Configure NVRAM settings

        From UBOOT dp.c:1165 signature:
        dp_configureNVRAM(randomRights, cyclicRights, randomSectors, cyclicSectors, fuseConfig)

        Returns:
            int: 0 = success, negative = error

        Assembly verification: cardManagerCLI:40499d
        """
        return self.__lib.configureNvram(
            card_path.encode('utf-8'),
            param1, param2, param3, param4, param5 & 0xFF
        )

    def get_protection_profiles(self, card_path: str, max_profiles: int = 8) -> tuple[int, list[ProtectionProfile]]:
        """Get protection profiles

        Returns:
            Tuple of (status_code, profiles)
            - status_code: int (0 = success, negative = error)
            - profiles: list of ProtectionProfile objects

        Assembly verification: cardManagerCLI:404bf2-404bfb (max=8 hardcoded at 404bf2)
        """
        profiles = (ProtectionProfile * max_profiles)()
        count = ctypes.c_uint(0)
        result = self.__lib.getProtectionProfiles(
            card_path.encode('utf-8'),
            ctypes.byref(count),
            profiles, max_profiles
        )
        profile_list = [profiles[i] for i in range(count.value)]
        return result, profile_list

    def set_protection_profiles(self, card_path: str, profiles: list[tuple[int, int]]) -> int:
        """Set protection profiles

        Args:
            profiles: List of (start_address, profile_type) tuples
                     profile_type from ProtectionType enum (0-6)

        Returns:
            int: 0 = success, negative = error

        Assembly verification: cardManagerCLI:4066ec-4066f2
        """
        profile_array = (ProtectionProfile * len(profiles))()
        for i, (start, ptype) in enumerate(profiles):
            profile_array[i].start_address = start
            profile_array[i].profile_type = ptype
        return self.__lib.setProtectionProfiles(card_path.encode('utf-8'), profile_array, len(profiles))

    def clear_protection_profiles(self, card_path: str) -> int:
        """Clear all protection profiles

        Returns:
            int: 0 = success, negative = error

        Assembly verification: cardManagerCLI:404a5e
        """
        return self.__lib.clearProtectionProfiles(card_path.encode('utf-8'))

    def challenge_firmware(self, card_path: str, input_data: bytes, mode: int = 0) -> tuple[int, bytes]:
        """Challenge firmware - PUF (Physically Unclonable Function) query.

        Reverse engineering analysis (libCardManagement.so:c1c0-c2da):

        APDU sent: FF F1 <mode> 00 20 <32 bytes input>
          - CLA: 0xFF
          - INS: 0xF1 (CHALLENGE_FIRMWARE)
          - P1:  mode (0-2, if 3 provided becomes 0 due to & 0x3 mask)
          - P2:  0x00
          - Lc:  0x20 (32 bytes)
          - Data: 32 bytes challenge

        Response: 32 bytes PUF-derived response

        Purpose: Firmware/device authenticity verification via PUF.
        The 3 modes (0-2) likely select different PUF challenge configurations.
        Response is derived from silicon manufacturing variations unique to each chip.

        Used for:
          - Device authentication (verify genuine SwissBit chip)
          - Key derivation (PUF output seeds device-unique keys)

        NOT useful for SCA: The "secret" is not stored data but inherent
        to silicon physical characteristics - cannot be extracted via
        power analysis.

        Args:
            card_path: Device path (e.g., "/dev/sdb")
            input_data: Exactly 32 bytes input (chosen plaintext)
            mode: Mode 0-2 (mode & 0x3 applied, so 3 becomes 0)

        Returns:
            Tuple of (status_code, 32-byte response)
            - status_code: int (0 = success, negative = error)
            - response: bytes (32 bytes cryptographic output)

        Assembly verification: libCardManagement.so:c1c0-c2da
        """
        assert len(input_data) == 32, "Input must be exactly 32 bytes!"
        assert 0 <= mode <= 3, "Mode must be 0-3"

        input_arr = self._bytes_to_array(input_data)
        output_arr = (ctypes.c_ubyte * 32)()

        result = self.__lib.challengeFirmware(
            card_path.encode('utf-8'),
            input_arr,
            output_arr,
            mode & 0x3
        )
        return result, bytes(output_arr)

    def get_application_version(self, card_path: str) -> tuple[int, int]:
        """Get application/firmware version

        Returns:
            Tuple of (status_code, version)
            - status_code: int (0 = success, negative = error)
            - version: int (version number, display as hex)

        Assembly verification: libCardManagement.so:5e70
        """
        version = ctypes.c_uint(0)
        result = self.__lib.getApplicationVersion(card_path.encode('utf-8'), ctypes.byref(version))
        return result, version.value

    def get_base_fw_version(self, card_path: str) -> tuple[int, str, str]:
        """Get base firmware version strings

        Returns:
            Tuple of (status_code, version1, version2)
            - status_code: int (0 = success, negative = error)
            - version1: str (first version string)
            - version2: str (second version string)

        Assembly verification: libCardManagement.so:5f60
        """
        version1 = ctypes.create_string_buffer(16)
        version2 = ctypes.create_string_buffer(16)
        result = self.__lib.getBaseFWVersion(card_path.encode('utf-8'), version1, version2)
        return result, version1.value.decode('utf-8', errors='replace'), version2.value.decode('utf-8', errors='replace')

    def get_overall_size(self, card_path: str) -> tuple[int, int]:
        """Get overall card size in sectors

        Tries USB interface first, falls back to SD.

        Returns:
            Tuple of (status_code, size_sectors)
            - status_code: int (0 = success, negative = error)
            - size_sectors: int (size in 512-byte sectors)

        Assembly verification: libCardManagement.so:6190
        """
        size = ctypes.c_uint(0)
        result = self.__lib.getOverallSize(card_path.encode('utf-8'), ctypes.byref(size))
        return result, size.value

    def get_partition_table(self, card_path: str) -> tuple[int, list[tuple[int, int]]]:
        """Get partition table (4 partitions)

        Returns:
            Tuple of (status_code, partitions)
            - status_code: int (0 = success, negative = error, 0x6f02 = not logged in)
            - partitions: list of 4 tuples (offset, size) in sectors

        Assembly verification: libCardManagement.so:6060
        """
        # 8 uint32 values: alternating offset/size for 4 partitions
        buffer = (ctypes.c_uint * 8)()
        result = self.__lib.getPartitionTable(card_path.encode('utf-8'), buffer)

        # Parse into (offset, size) tuples
        partitions = [
            (buffer[0], buffer[4]),  # partition 1
            (buffer[1], buffer[5]),  # partition 2
            (buffer[2], buffer[6]),  # partition 3
            (buffer[3], buffer[7]),  # partition 4
        ]
        return result, partitions

    def get_disk_size(self, card_path: str) -> int:
        """Get disk size in bytes using ioctl

        This is a simpler function that directly queries the OS
        for the disk size, not the card firmware.

        Returns:
            Disk size in bytes (0 on error)

        Assembly verification: libCardManagement.so:a890 (_Z11getDiskSizePKc)
        """
        return self.__lib._Z11getDiskSizePKc(card_path.encode('utf-8'))

    # =========================================================================
    # LOW-LEVEL APDU FUNCTIONS (for fuzzing/research)
    # =========================================================================

    def open_device(self, card_path: str) -> tuple[int, ctypes.c_void_p]:
        """Open device for low-level APDU access

        Returns:
            Tuple of (status_code, handle)
            - status_code: int (0 = success, negative = error)
            - handle: opaque handle for use with transmit_apdu/close_device
        """
        # FSI communication uses a special file on the card
        fsi_path = card_path.rstrip('/') + '/__communicationFile'

        handle = ctypes.c_void_p()
        result = self.__lib.fsi_open(
            fsi_path.encode('utf-8'),
            ctypes.byref(handle)
        )
        return result, handle

    def close_device(self, handle: ctypes.c_void_p) -> int:
        """Close device handle

        Returns:
            int: 0 = success, negative = error
        """
        return self.__lib.fsi_close(handle)

    def transmit_apdu(self, handle: ctypes.c_void_p, apdu: bytes) -> tuple[int, bytes, int]:
        """Transmit raw APDU and get response

        Args:
            handle: Device handle from open_device()
            apdu: Raw APDU bytes (CLA INS P1 P2 [Lc] [data] [Le])

        Returns:
            Tuple of (status_code, data, sw)
            - status_code: int (0 = success from fsi_transmit_se)
            - data: bytes (response data, excluding SW)
            - sw: int (status word SW1<<8 | SW2, or 0 on error)
        """
        cmd = (ctypes.c_ubyte * len(apdu)).from_buffer_copy(apdu)
        resp = (ctypes.c_ubyte * 256)()
        resp_len = ctypes.c_uint(256)

        result = self.__lib.fsi_transmit_se(handle, cmd, len(apdu), resp, ctypes.byref(resp_len))

        if resp_len.value >= 2:
            sw = (resp[resp_len.value - 2] << 8) | resp[resp_len.value - 1]
            data = bytes(resp[:resp_len.value - 2])
        else:
            sw = 0
            data = b''

        return result, data, sw
