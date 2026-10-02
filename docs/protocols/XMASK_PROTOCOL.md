# Flexxon X-Mask PRO Protocol Specification

Reverse engineered from XMASK_PRO_SETUP_WIN64_V1.0.6.exe

## Overview

The X-Mask PRO secure SD card uses SD CMD56 (GEN_CMD) vendor-specific commands for security operations. Communication is tunneled through SCSI passthrough when using USB card readers.

## Transport Layer

### USB Card Reader (UT33x)

When using compatible USB card readers (UT33x chip), the application communicates via SCSI passthrough:

| Operation    | SCSI OpCode | Sub-opcode | Flag |
|--------------|-------------|------------|------|
| CMD56 Read   | 0xF8        | 0x31       | 1    |
| CMD56 Write  | 0xF8        | 0x32       | 0    |

**CDB Structure (12 bytes):**
```
Offset 0: OpCode (0xF8)
Offset 1: Sub-opcode (0x31=read, 0x32=write)
Offset 2-7: Command parameters
Offset 8-11: Transfer length (0x200 = 512 bytes)
```

### Direct SD Access

For native SD interfaces, CMD56 is issued directly:
- CMD56 Read: GEN_CMD with RD/WR=1
- CMD56 Write: GEN_CMD with RD/WR=0

## Command Buffer Structure (512 bytes)

All commands use a 512-byte data buffer. Buffer is zeroed first, then populated:

### Byte-Level Layout

| Offset | Size | Value/Description                                     |
|--------|------|-------------------------------------------------------|
| 0x000  | 8    | Identifier (8-byte card name, normal byte order)      |
| 0x008  | 240  | Reserved (zero-filled)                                |
| 0x0F8  | 1    | Identifier byte 7 (MSB)                               |
| 0x0F9  | 1    | Identifier byte 6                                     |
| 0x0FA  | 1    | Identifier byte 5                                     |
| 0x0FB  | 1    | Identifier byte 4                                     |
| 0x0FC  | 1    | Identifier byte 3                                     |
| 0x0FD  | 1    | Identifier byte 2                                     |
| 0x0FE  | 1    | Identifier byte 1                                     |
| 0x0FF  | 1    | Identifier byte 0 (LSB)                               |
| 0x100  | 1    | Command type = **0x02**                               |
| 0x101  | 1    | Parameter = **0x01**                                  |
| 0x102  | 1    | Parameter = 0x00                                      |
| 0x103  | 1    | Parameter = 0x00                                      |
| 0x104  | 1    | Parameter = 0x00                                      |
| 0x105  | 1    | Parameter = 0x00                                      |
| 0x106  | 1    | Parameter = 0x00                                      |
| 0x107  | 1    | Parameter = 0x00                                      |
| 0x108  | 1    | **Function selector** (see command codes below)       |
| 0x109  | ...  | Payload area (varies by command type, see below)      |
| 0x1F8  | 8    | Trailer: **00 00 00 00 00 00 01 02** (little endian)  |

### Payload Area Variants

**Mode 2 Enter (basic, no password):**

| Offset | Size | Description                                           |
|--------|------|-------------------------------------------------------|
| 0x109  | 3    | Reserved (zeros)                                      |
| 0x10C  | 4    | Magic: **DE AD BE EF** (only when security mode=3)    |
| 0x110  | 232  | Reserved (zeros)                                      |

**SDKey Enter (with password):**

| Offset | Size | Description                                           |
|--------|------|-------------------------------------------------------|
| 0x109  | 64   | Password (XOR encrypted, 64 bytes)                    |
| 0x149  | 1    | XOR key (random 1-254)                                |
| 0x14A  | 174  | Reserved (zeros)                                      |

**SDKey Enter with secondary password (func=0x02):**

| Offset | Size | Description                                           |
|--------|------|-------------------------------------------------------|
| 0x109  | 32   | Primary password (XOR encrypted)                      |
| 0x129  | 32   | Secondary password (XOR encrypted with same key)      |
| 0x149  | 1    | XOR key (random 1-254)                                |
| 0x14A  | 174  | Reserved (zeros)                                      |

### Example Command Buffer (Set Password, func=0x08)

```
Offset    00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F
--------  -----------------------  -----------------------
0x000     58 4D 41 53 4B 50 52 4F  00 00 00 00 00 00 00 00  ; "XMASKPRO" + padding
0x010     00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ; zeros
...
0x0F0     00 00 00 00 00 00 00 00  4F 52 50 4B 53 41 4D 58  ; zeros + reversed ID
0x100     02 01 00 00 00 00 00 00  08 XX XX XX XX XX XX XX  ; cmd=02, param=01, func=08, password
0x110     XX XX XX XX XX XX XX XX  XX XX XX XX XX XX XX XX  ; password continued (XOR'd)
...
0x140     XX XX XX XX XX XX XX XX  XX YY 00 00 00 00 00 00  ; password end, YY=XOR key
...
0x1F0     00 00 00 00 00 00 00 00  00 00 00 00 00 00 01 02  ; trailer
```

Where:
- `58 4D 41 53 4B 50 52 4F` = "XMASKPRO" (example identifier)
- `XX` = password bytes XOR'd with key `YY`
- `YY` = random XOR key (1-254)

### Identifier Format

The identifier at offset 0x00 is an 8-byte string derived from the card name. At offset 0xF8, the same bytes appear in reversed order (byte 7 at 0xF8, byte 6 at 0xF9, etc.).

### Enter vs Leave Pattern

The Enter and Leave commands use inverted identifier placement:

**Enter Special Mode 2:**
```
Offset 0x00-0x07: Identifier (normal order)
Offset 0xF8-0xFF: Identifier (reversed, MSB first)
```

**Leave Special Mode 2:**
```
Offset 0x00-0x07: Identifier (reversed, MSB first)
Offset 0xF8-0xFF: Identifier (normal order)
```

This inversion distinguishes enter from leave commands.

### Password Encryption

Password is stored at offset 0x109 with simple XOR encryption:
1. Generate random XOR key (1-254) using Mersenne Twister PRNG
2. XOR each byte of password (up to 64 bytes) with the key
3. Store XOR key at offset 0x149

```c
for (int i = 0; i < 64; i++) {
    buffer[0x109 + i] = password[i] ^ xor_key;
}
buffer[0x149] = xor_key;
```

## Function Selectors

### Mode 2 Commands (Basic Security)

These commands use `EnterSpecialMode2` with mode=0x02:

| Code | Function                | Description                           |
|------|-------------------------|---------------------------------------|
| 0x05 | ReadHeader              | Read security header/status           |
| 0x06 | CertificationKey        | Verify/authenticate password          |
| 0x07 | ResetKey                | Remove password protection            |
| 0x08 | SetKey                  | Set new password                      |
| 0x09 | SetPartitionStartLBA    | Configure partition start             |
| 0x0A | TempUnlock              | Temporary unlock session              |

### SDKey Mode Commands (Extended Security)

These commands use `EnterSpecialMode2WithSDKey`:

| Code | Function                | Description                           |
|------|-------------------------|---------------------------------------|
| 0x14 | ReadInfoHeader          | Read card info with SDKey auth        |
| 0x15 | SetPassword             | Set password via SDKey                |
| 0x16 | RemovePassword          | Remove password via SDKey             |
| 0x17 | TempUnlockSecure        | Temporary unlock with SDKey           |
| 0x18 | Reserved                | Unknown                               |
| 0x19 | Reserved                | Unknown                               |
| 0x1A | Authenticate            | SDKey authentication                  |

## Binary Cross-Reference (File 44)

All addresses are relative to image base (add 0x400000 for VA).

### Public SDK API Functions

| Function                | Address    | Description                           |
|-------------------------|------------|---------------------------------------|
| SDKOpenDiskHandle       | 0x05e8c0   | Open device handle                    |
| SDKFreeDeviceHandle     | 0x060360   | Close device handle                   |
| SDKCheckSupport         | 0x060440   | Check if card is supported            |
| SDKSetDiskName          | 0x05fd30   | Set disk identifier                   |
| SDKSetConfigPath        | 0x060750   | Set configuration path                |
| SDKGetErrorMessage      | 0x05fd00   | Get last error message                |
| SDKGetStatus            | 0x061350   | Get card security status              |
| **SDKSetPassword**      | 0x061310   | Set new password                      |
| **SDKRemovePassword**   | 0x0612b0   | Remove password                       |
| **SDKTempDisableSecure**| 0x0612d0   | Temporary unlock                      |
| **SDKAuthentication**   | 0x0612f0   | Authenticate with password            |
| **SDKSetCurrentSDKey**  | 0x061330   | Set current active key                |

### Internal Security Functions

| Function                | Address    | Calls                                 |
|-------------------------|------------|---------------------------------------|
| SetSDKey                | 0x05f080   | LoadDll_Main(0x08)                    |
| CleanSDKey              | 0x05f330   | LoadDll_Main(0x06,0x05,0x07)          |
| TempUnlockSecure        | 0x05f5d0   | LoadDll_Main(0x06,0x05,0x0a)          |
| CertificationSDKey      | 0x05ecd0   | LoadDll_Main(0x06)                    |
| SetCurrentSDKey         | 0x05ef50   | Updates current key state             |

### Command Dispatcher Functions

| Function                | Address    | Description                           |
|-------------------------|------------|---------------------------------------|
| LoadDll_Main            | 0x062c20   | Main command dispatcher               |
| LoadDll_Main_SDKey      | 0x063490   | SDKey command dispatcher              |
| LoadDll_Main_Uncrypted  | 0x063240   | Uncrypted command dispatcher          |

### CSmartInfoReader Methods

| Method                  | Address    | Func Code | Description                   |
|-------------------------|------------|-----------|-------------------------------|
| Execute                 | 0x06a0f0   | varies    | Execute command by code       |
| ReadHeader              | 0x06a910   | 0x05      | Read security header          |
| CertificationKey        | 0x06b2d0   | 0x06      | Verify password               |
| ResetKey                | 0x06ac10   | 0x07      | Remove password               |
| SetKey                  | 0x06afd0   | 0x08      | Set new password              |
| SetPartitionStartLBA    | 0x06b0e0   | 0x09      | Set partition LBA             |
| TempUnlock              | 0x06aec0   | 0x0a      | Temporary unlock              |
| GetSecurityInfo         | 0x06a800   | -         | Read security status          |
| ReadDataOfSmartV2ForSecurity | 0x06a690 | varies | Security data reader        |
| ReadDataOfSmartV2ForSDKey    | 0x06a740 | varies | SDKey data reader           |

### CSpecialMode2Cmd Methods

| Method                        | Address    | Description                     |
|-------------------------------|------------|---------------------------------|
| EnterSpecialMode2             | 0x075510   | Enter mode 2 (basic)            |
| EnterSpecialMode2WithSDKey    | 0x0757e0   | Enter mode 2 with password      |
| LeaveSpecialMode2             | 0x075b30   | Exit mode 2                     |
| CreateMode2EnterPattern       | 0x0755e0   | Build enter command buffer      |
| CreateMode2LeavePattern       | 0x075c60   | Build leave command buffer      |
| CreateSDKeyEnterPattern       | 0x0758c0   | Build SDKey command buffer      |
| Cmd25                         | 0x076020   | Low-level CMD25 (write multi)   |
| Cmd27                         | 0x075ef0   | Low-level CMD27                 |
| Cmd18                         | 0x076200   | Low-level CMD18 (read multi)    |
| UpdateSDKey                   | 0x075e00   | Update key in card              |

### DigiKey Functions (Alternative Key System)

| Function                | Address    | Description                           |
|-------------------------|------------|---------------------------------------|
| DigiKeyGetKey           | 0x0607a0   | Retrieve digital key                  |
| DigiKeySetKey           | 0x060a80   | Set digital key                       |
| DigiKeyVerifyKey        | 0x060ee0   | Verify digital key                    |

## SDK Function Mapping

| SDK API Function      | Internal Function      | Code  | Address    |
|-----------------------|------------------------|-------|------------|
| SDKSetPassword        | SetSDKey               | 0x08  | 0x061310→0x05f080 |
| SDKRemovePassword     | CleanSDKey             | 0x07  | 0x0612b0→0x05f330 |
| SDKTempDisableSecure  | TempUnlockSecure       | 0x0A  | 0x0612d0→0x05f5d0 |
| SDKAuthentication     | CertificationSDKey     | 0x06  | 0x0612f0→0x05ecd0 |
| SDKSetCurrentSDKey    | SetCurrentSDKey        | -     | 0x061330→0x05ef50 |

## Call Flow Diagram

```
SDK API Layer (exported functions)
├── SDKSetPassword (0x061310)
│   └── SetSDKey (0x05f080)
│       └── LoadDll_Main(0x08) (0x062c20)
│           ├── FlushAndUnmountDevice
│           ├── FillKeyValue
│           ├── SetCardFunction
│           ├── Execute(0x05) → ReadHeader
│           └── Execute(0x08) → SetKey
│               └── CSmartInfoReader::SetKey (0x06afd0)
│                   └── EnterSpecialMode2WithSDKey (0x0757e0)
│                       └── CreateSDKeyEnterPattern (0x0758c0)
│                           └── [builds 512-byte buffer]
│                               └── CMD56 Write via SCSI/USB
│
├── SDKAuthentication (0x0612f0)
│   └── CertificationSDKey (0x05ecd0)
│       └── LoadDll_Main(0x06) (0x062c20)
│           └── Execute(0x06) → CertificationKey
│               └── CSmartInfoReader::CertificationKey (0x06b2d0)
│
├── SDKRemovePassword (0x0612b0)
│   └── CleanSDKey (0x05f330)
│       └── LoadDll_Main(0x06), LoadDll_Main(0x05), LoadDll_Main(0x07)
│           └── Execute(0x07) → ResetKey
│               └── CSmartInfoReader::ResetKey (0x06ac10)
│
└── SDKTempDisableSecure (0x0612d0)
    └── TempUnlockSecure (0x05f5d0)
        └── LoadDll_Main(0x06), LoadDll_Main(0x05), LoadDll_Main(0x0a)
            └── Execute(0x0a) → TempUnlock
                └── CSmartInfoReader::TempUnlock (0x06aec0)
```

## Command Sequence

### Authentication Flow

1. **Enter Special Mode 2**
   - Send CMD56 Write with function selector 0x02
   - Buffer contains identifier and mode

2. **Execute Command**
   - Send CMD56 Write with function selector (e.g., 0x06 for auth)
   - Include XOR-encrypted password

3. **Read Response**
   - Send CMD56 Read to get status/result

4. **Leave Special Mode 2** (two-step process)
   - Send CMD56 Write with Enter pattern (normal identifier)
   - Send CMD56 Write with Leave pattern (reversed identifier)

### Set Password Flow

```
1. FlushAndUnmountDevice()
2. FillKeyValue(password)
3. SetCardFunction(function_code)
4. Execute(0x05)  // Read current status
5. Execute(0x08)  // Set new key
```

### Remove Password Flow

```
1. SetCurrentSDKey()
2. LoadDll_Main(0x06)  // Enter mode
3. LoadDll_Main(0x05)  // Read status
4. LoadDll_Main(0x07)  // Reset key (if mode 3)
```

### Temporary Unlock Flow

```
1. SetCurrentSDKey()
2. LoadDll_Main(0x06)  // Enter mode
3. LoadDll_Main(0x05)  // Read status
4. LoadDll_Main(0x0A)  // Temp unlock (if mode 3)
```

## Response Structure

Response is read via CMD56 Read into a 512-byte buffer:

| Offset | Description                              |
|--------|------------------------------------------|
| 0x49   | Status/result code                       |
| 0x1C1  | Security mode (0x03 = advanced mode)     |

## Security Observations

1. **Weak XOR Encryption**: Password is only XOR'd with a single-byte key
2. **Key in Buffer**: XOR key is transmitted alongside encrypted password
3. **No Replay Protection**: No nonce/counter visible in command structure
4. **Predictable PRNG**: Mersenne Twister seeded from system time

## Implementation Notes

- Buffer size is always 512 bytes (one SD sector)
- Commands require device to be unmounted first
- UT33x reader chip provides SCSI-to-CMD56 translation
- Mode 3 (at offset 0x1C1) indicates advanced HDS security

## Comparison with Swissbit PS-66u

| Feature              | Flexxon X-Mask        | Swissbit PS-66u       |
|----------------------|-----------------------|-----------------------|
| Authentication       | Single password       | PIN + SO-PIN          |
| Protocol             | Proprietary CMD56     | ISO 7816-4 APDU       |
| Encryption           | XOR (single byte key) | Challenge-response    |
| Certification        | None                  | FIPS 140-3 Level 3    |
| Partitions           | Single                | Multiple (CD-ROM+RW)  |
