# Swissbit SD Card FSI Protocol - Reverse Engineering Documentation

## Overview

This document describes the File System Interface (FSI) protocol used by Swissbit secure SD cards for security operations. The protocol tunnels smartcard-style APDU commands through standard SD card block read/write operations.

## Discovery Method

Protocol reverse-engineered using:
1. Saleae Logic Analyzer with custom SDIO analyzer (extended to capture DAT0 data blocks)
2. Captures of `cardManagerCLI` from Swissbit's SecurityUpgradeKit_Tools_Linux
3. Analysis of `libCardManagement.so` strings

## Key Finding: FAT Allocation Required

**Critical**: The SD card firmware does NOT trigger FSI processing based solely on the 32-byte identifier. The card requires that the target sector belongs to an **allocated cluster in the FAT**.

The `cardManagerCLI` creates a file called `__communicationFile` and writes FSI commands to its data clusters. The card firmware monitors writes to allocated clusters and intercepts those containing the FSI identifier.

## Protocol Details

### FAT32 Layout (Card-Specific Example)

```
Reserved region:  sectors 0 - 8613
FAT1:             sectors 8614 - 12498 (3885 sectors)
FAT2:             sectors 12499 - 16383 (3885 sectors)
Data region:      starts at sector 16384 (0x4000)
Cluster size:     64 sectors (32KB)
```

### FSI Transaction Sequence

For each FSI command, the following sequence is required:

```
1. WRITE FAT1_sector   [0x0FFFFFFF at entry offset]  (allocate cluster)
2. WRITE FAT2_sector   [0x0FFFFFFF at entry offset]  (allocate cluster)
3. WRITE data_sector   [identifier + FSI command]    (send command)
4. READ  data_sector   [FSI response]                (receive response)
5. WRITE FAT1_sector   [0x00000000 at entry offset]  (free cluster)
6. WRITE FAT2_sector   [0x00000000 at entry offset]  (free cluster)
```

The same cluster can be reused repeatedly (allocate, use, free cycle).

### FSI Command Block Format (512 bytes)

```
Offset  Size  Description
------  ----  -----------
0x00    32    Identifier (fixed magic bytes)
0x20    1     Direction (0x01 for command)
0x21    1     Flags (0x00)
0x22    2     APDU Length (BIG-ENDIAN!)
0x24    N     APDU data
0x26+N  ...   Padding (zeros)
```

### 32-Byte Identifier

```
10 6A F8 1A D6 F8 C8 70 AC 7E 85 F0 E9 9E F3 9D
1E 11 A1 BA 87 4A C6 DB 42 81 15 8E FE 6D 3C 81
```

### FSI Response Block Format (512 bytes)

```
Offset  Size  Description
------  ----  -----------
0x00    1     Direction (0x03 for response)
0x01    1     Flags
0x02    2     Response Length (BIG-ENDIAN!)
0x04    N     Response data (includes SW1-SW2 at end)
```

### APDU Format

Standard ISO 7816-4 APDU structure:

```
CLA = 0xFF (Swissbit proprietary class)
INS = Command instruction
P1  = Parameter 1 (subcommand for INS_GET)
P2  = Parameter 2 (usually 0x00)
Le  = Expected response length (0x00 = maximum)
```

### Supported Commands

| INS  | Name            | P1 Values                    |
|------|-----------------|------------------------------|
| 0x10 | ACTIVATE        | -                            |
| 0x20 | DEACTIVATE      | -                            |
| 0x30 | VERIFY          | -                            |
| 0x31 | LOCK            | -                            |
| 0x40 | CHANGE_PASSWORD | -                            |
| 0x53 | RESET           | -                            |
| 0x70 | GET             | 0x00=Status, 0x01=CardID, 0x02=AppVersion, 0x05=Challenge, 0x06=ControllerID |

### Status Words (SW1-SW2)

| SW     | Meaning        |
|--------|----------------|
| 0x9000 | Success        |
| 0x6700 | Wrong length   |

### Example: GET_STATUS

Command APDU:
```
FF 70 00 00 00
```

Response (17 bytes):
```
40 02 0A 0F 00 00 00 01 00 00 00 00 00 00 33 90 00
                                          ^^^^^
                                          SW=9000
```

## Implementation Notes

### Cluster/Sector Mapping

For SDHC cards, CMD17/CMD24 use **block addresses** (not byte addresses).

```
cluster_sector = data_region_start + (cluster_number - 2) * sectors_per_cluster
```

### FAT Entry Calculation

```
fat_sector = fat_start + (cluster_number / 128)
entry_offset = (cluster_number % 128) * 4
```

Each FAT sector contains 128 entries (512 bytes / 4 bytes per entry).

### Timing Considerations

After card initialization, a small delay (~200ms) may be required before the first block read succeeds. Retry logic is recommended.

## Hardware Setup

### Saleae Logic Analyzer
- Channels: CLK, CMD, DAT0 (minimum for 1-bit mode)
- Sample rate: 25MHz+ recommended
- Use custom SDIO analyzer with data block capture

### GreatFET One
- SDIO peripheral for direct card access
- Clock divider 25 (~1MHz) works reliably
- Firmware must support CMD17/CMD24 with data transfer

### Card Reader Modification (for UHS-I cards)
Disable UHS-I by taping microSD pins 2 and 3 (or use reader without UHS-I support) to force legacy timing compatible with logic analyzer capture.

## Files

- `swissbit_fsi.py` - Working GreatFET FSI implementation
- `sdio_host.py` - GreatFET SDIO host driver
- `SDIOAnalyzer/` - Saleae SDIO analyzer with data capture

## References

- SD Physical Layer Simplified Specification
- ISO/IEC 7816-4 (APDU structure)
- Swissbit SecurityUpgradeKit documentation
