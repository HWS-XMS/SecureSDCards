# Swissbit FSI Protocol - Reverse Engineered

## Overview
Swissbit secure SD cards use a File System Interface (FSI) protocol for security commands.
Communication happens via a special file `__communicationFile` on the mounted filesystem.

## Communication Channel
- **File**: `<mountpoint>/__communicationFile`
- **Open flags**: `O_RDWR | O_CREAT | O_SYNC | O_DIRECT`
- **Block size**: 512 bytes (aligned I/O required due to O_DIRECT)

## Protocol Sequence (from strace analysis)

For EACH command, the sequence is:

### Step 1: Open file
```c
openat(AT_FDCWD, "<mountpoint>/__communicationFile", O_RDWR|O_CREAT|O_SYNC|O_DIRECT, 0664)
```

### Step 2: Write initialization block (512 bytes)
```
"PLEASE DO NOT DELETE THIS FILE!" + 480 zero bytes
```
Note: File is NOT deleted - just marker text.

### Step 3: Seek to beginning
```c
lseek(fd, 0, SEEK_SET)
```

### Step 4: Write FSI command block (512 bytes)

| Offset | Size | Description |
|--------|------|-------------|
| 0x00   | 32   | Identifier (magic bytes) |
| 0x20   | 1    | Direction: 0x01=SE (send), 0x00=FC |
| 0x21   | 1    | Flags: 0x00 |
| 0x22   | 2    | APDU length (big-endian) |
| 0x24   | var  | APDU data |

### Step 5: Seek to beginning again
```c
lseek(fd, 0, SEEK_SET)
```

### Step 6: Read response (512 bytes)

| Offset | Size | Description |
|--------|------|-------------|
| 0x00   | 1    | Direction: 0x03=SE response, 0x02=FC response |
| 0x01   | 1    | Flags |
| 0x02   | 2    | Response length (BIG-endian!) |
| 0x04   | var  | Response data + SW (last 2 bytes) |

**CRITICAL**: The file is reopened for EACH command exchange!

## 32-Byte Identifier
```
10 6a f8 1a d6 f8 c8 70 ac 7e 85 f0 e9 9e f3 9d
1e 11 a1 ba 87 4a c6 db 42 81 15 8e fe 6d 3c 81
```

## APDU Format
Standard ISO7816-4 APDU with CLA=0xFF:

| Byte | Description |
|------|-------------|
| CLA  | 0xFF (Swissbit class) |
| INS  | Instruction code |
| P1   | Parameter 1 |
| P2   | Parameter 2 |
| Lc   | Data length (0x00 if no data) |
| Data | Optional command data |

**Note**: APDUs use Lc (command data length), NOT Le (expected response length)!

## Instruction Codes (INS)

| INS  | Command |
|------|---------|
| 0x10 | ACTIVATE |
| 0x20 | DEACTIVATE |
| 0x30 | VERIFY |
| 0x31 | LOCK |
| 0x40 | CHANGE_PASSWORD |
| 0x53 | RESET |
| 0x70 | GET |

## GET Subcommands (P1 values for INS=0x70)

| P1   | Command | Response |
|------|---------|----------|
| 0x00 | GET_STATUS | 17 bytes status |
| 0x01 | GET_CARD_ID | 16 bytes card ID |
| 0x02 | GET_APP_VERSION | 4 bytes version |
| 0x04 | GET_PARTITION_OFFSET | offset info |
| 0x05 | GET_CHALLENGE | challenge for auth |
| 0x06 | GET_CONTROLLER_ID | 12 bytes controller ID |

## Status Word (SW)

| SW     | Meaning |
|--------|---------|
| 0x9000 | Success |
| 0x6700 | Wrong length |
| 0x6E00 | Class not supported |

## Example: GET_STATUS

**Command APDU**: `FF 70 00 00 00`
- CLA=0xFF, INS=0x70 (GET), P1=0x00 (STATUS), P2=0x00, Lc=0x00

**FSI Block** (hex):
```
106af81ad6f8c870ac7e85f0e99ef39d1e11a1ba874ac6db4281158efe6d3c81  (identifier)
01 00 05 00  (dir=SE, flags=0, len=5 LE)
ff 70 00 00 00  (APDU)
00...  (padding to 512 bytes)
```

**Response** (from strace):
```
03 00 00 11  (dir=0x03, flags=0, len=17 BE)
40 02 0a 0f 00 00 00 01 00 00 00 33 90 00  (17 bytes: data + SW)
```

Response data breakdown:
- Byte 0: License mode (0x40)
- Byte 1: Card status (0x02)
- Byte 2: User retry counter (0x0A = 10)
- Byte 3: SO retry counter (0x0F = 15)
- Bytes 4-7: Number of resets
- Byte 8-11: Extended flags
- Bytes 12-13: SW 0x9000

## Raw SDIO Notes

When using raw SDIO (not filesystem):
- The `__communicationFile` is located at **sector 4** (byte offset 0x800)
- Same FSI protocol applies
- Card may timeout if SDIO timing is incorrect
- Card works fine via normal filesystem access

## Key Findings

1. **Endianness differs**: Command length is little-endian, response length is big-endian
2. **APDU format**: Use Lc (data length), not Le (expected response length)
3. **Initialization required**: Write "PLEASE DO NOT DELETE THIS FILE!" first
4. **O_DIRECT required**: Filesystem I/O must be aligned and direct

## Raw SDIO Testing Results (GreatFET)

### What Works
- Card initialization (CMD0, CMD8, ACMD41, CMD2, CMD3, CMD7) succeeds
- Card enters transfer state correctly
- Writing init block to sector 4 succeeds
- Writing FSI command block to sector 4 succeeds (sometimes)
- Card DOES respond with SW 0x6700 ("wrong length") - proving FSI is recognized

### What Fails
- Card times out (-116) inconsistently after 1-2 operations
- After timeout, card requires power cycle to recover
- Hexdump of sector 4 on disk shows only raw APDU bytes, not FSI header
  - This confirms: FSI protocol is handled by card firmware, not stored on disk
  - The `__communicationFile` write triggers internal card processing

### Critical Discovery
When we hexdumped sector 4 via Linux after cardManagerCLI:
```
00000800  ff 70 00 00 00 00 00 00  ...
```
Only the APDU is visible, NOT the 32-byte identifier. This means:
- The USB card reader / filesystem driver does something special
- The card intercepts FSI writes and processes them internally
- The identifier is NOT written to physical media

### Next Step: Logic Analyzer
Need to capture actual SD bus traffic from USB card reader to see:
- What SD commands are sent (CMD24? CMD56? Something else?)
- Timing between commands
- Any special flush/sync commands

### Hardware Setup
- Logic analyzer: 500 MS/s (sufficient for 50 MHz SD clock)
- Probe points: SD socket pins CLK(5), CMD(3), DAT0(7), GND(6)
- USB card reader: GL3293 (Genesys Logic USB 3.0 controller)

### Card Info
- Manufacturer: Swissbit
- CID: 5D50534E31445035101A6CD5C201894F
- Controller ID: 0746288024110518182e0c09
- App version: 176
- Firmware: 220802s9 108
