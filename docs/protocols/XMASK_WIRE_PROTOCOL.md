# X-Mask Wire Protocol Specification

Reverse engineered from Saleae logic analyzer traces of Flexxon X-Mask SD card.

## Key Discovery: LBA-Based Command Dispatch

Unlike CMD56 vendor commands, X-Mask uses **standard CMD17/CMD24 at magic LBAs** to communicate with the security controller. The card intercepts writes to specific LBAs when they contain the identifier pattern.

## Card Identifier

From traces, this card's identifier is:
- **Normal order**: `36 39 36 36 38 33 30 31` = ASCII "69668301"
- **Reversed**: `31 30 33 38 36 36 39 36` = ASCII "10386696"

## Command Mapping

| Function | LBA | SD Command | Direction | Purpose |
|----------|-----|------------|-----------|---------|
| Enter Mode | 0 | CMD24 | Write | Send enter pattern to activate special mode |
| Leave Mode | 0 | CMD24 | Write | Send leave pattern to exit special mode |
| Read Header | 5 | CMD17 | Read | Read security status/header (512B) |
| Authentication | 6 | CMD24 | Write | Send encoded password for verification |
| Remove Password | 7 | CMD24 | Write | Reset/remove password protection |
| Set Password | 8 | CMD24 | Write | Set new password |
| Set Password Alt | 9 | CMD24 | Write | Alternative password set (observed in traces) |
| TempUnlock | 10 (0x0A) | CMD24 | Write | Temporarily unlock partition |

**The function code maps directly to the target LBA!**

## Buffer Formats

### Enter Pattern (CMD24 to LBA 0)

```
Offset 0x000-0x007: Identifier normal   "69668301" (8 bytes)
Offset 0x008-0x0F7: Zeros (240 bytes)
Offset 0x0F8-0x0FF: Identifier reversed "10386696" (8 bytes)
Offset 0x100:       Command type = 0x02
Offset 0x101:       Parameter = 0x01
Offset 0x102-0x107: Zeros
Offset 0x108:       Function selector (not used for basic enter)
Offset 0x109-0x1F7: Zeros
Offset 0x1F8-0x1FF: Trailer = 00 00 00 00 00 00 01 02
```

**Hex dump from trace (line 1861):**
```
0000: 36 39 36 36 38 33 30 31 00 00 00 00 00 00 00 00  69668301........
...
00F0: 00 00 00 00 00 00 00 00 31 30 33 38 36 36 39 36  ........10386696
0100: 02 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
...
01F0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 02  ................
```
CRC16: 0x3CE8

### Leave Pattern (CMD24 to LBA 0)

Same structure as Enter, but:
- Identifiers swapped (reversed at 0x00, normal at 0xF8)
- Parameter at 0x101 = 0x00 (instead of 0x01)
- Bytes at 0x102-0x107 = `00 00 00 00 01 02`
- Trailer at 0x1F8-0x1FF = `02 01 00 00 00 00 00 00`

```
Offset 0x000-0x007: Identifier REVERSED "10386696"
Offset 0x008-0x0F7: Zeros (240 bytes)
Offset 0x0F8-0x0FF: Identifier NORMAL   "69668301"
Offset 0x100:       Command type = 0x02
Offset 0x101:       Parameter = 0x00 (Leave)
Offset 0x102-0x107: 00 00 00 00 01 02
Offset 0x108-0x1F7: Zeros
Offset 0x1F8-0x1FF: Trailer = 02 01 00 00 00 00 00 00
```
CRC16: 0x21F1

### Security Header Response (CMD17 from LBA 5)

512 bytes returned containing card status and configuration:

```
Offset 0x00-0x02:  Magic "SI0" (0x53 0x49 0x30)
Offset 0x03-0x07:  Model "ET1288"
Offset 0x08:       0x00
Offset 0x09-0x0A:  Capacity code (0x9003)
Offset 0x0B:       Feature flags (0xA2)
...
Offset 0x21:       Status flags
Offset 0x2D:       Mode indicator
Offset 0x31:       Config byte 1
Offset 0x32:       Config byte 2
...
Offset 0x49:       Auth result / status byte (KEY FIELD)
...
Offset 0x58-0x5F:  Model string "FLXmD"
Offset 0x60-0x77:  Firmware info
...
Offset 0xB0-0xFF:  Scramble key area (readable without auth!)
...
Offset 0x1F6-0x1FF: Trailer with checksum
```

**Key status fields observed:**
- `0x1500050102` at offset 0x21 = security disabled
- `0x0F00050102` at offset 0x21 = mask mode enabled
- `0x0F05050102` at offset 0x21 = mask mode, needs auth
- Offset 0x49: `0x00` = success, `0x01` = need auth, `0xFF` = locked

### Encoded Password Buffer (CMD24 to LBA 6/8/9)

When authenticating (LBA 6) or setting password (LBA 8/9):

```
Offset 0x000-0x1FF: Layer 2 encoded data (512 bytes)
```

The entire buffer is scrambled using:
1. 32-bit Mersenne Twister PRNG XOR (128 iterations = 512 bytes)
2. CBitArray bit reordering permutation
3. 16-bit checksum at offset 0x1FE-0x1FF

**Example from `mask_mode_enabled_"P4ssw0rd!".csv` (line 71, LBA 9):**
```
0000: BB 4F CA 1B A7 71 58 30 02 E3 FB 4E 97 54 7F 18  .O...qX0...N.T..
0010: 7C 0A B5 48 AD CF 99 3B 94 DF C1 4A 1F 44 62 41  |..H...;...J.DbA
...
01F0: 39 D9 77 76                                      9.wv
```

## Command Sequences (from traces)

### Read Status (no auth required)

```
1. CMD24 to LBA 0: Enter pattern (×2, duplicated)
2. CMD24 to LBA 0: Leave pattern (identifier swapped)
3. CMD24 to LBA 0: Enter pattern
4. CMD17 from LBA 5: Read header (get status)
5. CMD24 to LBA 0: Enter pattern
6. CMD24 to LBA 0: Leave pattern
```

### Authentication Flow

```
Session 1: Enter → Write encoded password to LBA 6 → Leave
Session 2: Enter → Read header from LBA 5 (check result) → Leave
```

Observed sequence from `disable_mask.csv`:
```
Line 67-81:
  CMD24 LBA 0: Enter pattern ×2
  CMD24 LBA 0: Leave pattern (swapped)
  CMD24 LBA 0: Enter pattern
  CMD17 LBA 5: Read header (status check)
  CMD24 LBA 0: Enter ×2, Leave

Line 69-71:
  CMD24 LBA 6: Encoded password (auth attempt)
  ... Leave sequence
  CMD17 LBA 5: Read result
```

### Set Password Flow

From `mask_mode_enabled_"P4ssw0rd!".csv`:
```
1. Enter sequence
2. CMD17 LBA 5: Read current status
3. Leave sequence
4. Enter sequence
5. CMD24 LBA 9: Write encoded password (SetKey)
6. Leave sequence
7. Enter sequence
8. CMD17 LBA 5: Verify new status
9. Leave sequence
```

### Temporary Unlock Flow

From `plug_out_plug_in_XMASK_detected_masked_mode_temporary_disabled.csv`:
```
Lines 1859-1896:
1. CMD24 LBA 0: Enter ×2
2. CMD24 LBA 0: Leave
3. CMD24 LBA 0: Enter
4. CMD17 LBA 5: Read header
5. CMD17 LBA 5: Read header (second read with scrambled data)
6. CMD24 LBA 0: Enter, Leave

[After successful auth shown in header offset 0x49]
Lines 1897+: Data access now works (LBA 0 returns 0xFF... = empty/unlocked)
```

## Security Observations

### No Authentication Lockout
Traces show repeated Enter/Leave cycles with no penalty. Card accepts unlimited attempts.

### Scramble Key is Public
The 512-byte header at LBA 5 contains the scramble key (offset ~0xB0+) and is readable without authentication.

### Encoding is Transport-Only
Both encoding layers (single-byte XOR and 32-bit PRNG+permutation) are:
- Seeded from host-controlled values
- Fully reversible by anyone with the card

### Timing Consistency
All CMD24 data transfers take ~82μs. No timing variation observed between success/failure that would indicate early-exit comparison.

## Implementation Notes

### To Read Card Status
```python
def read_status(sd):
    # Enter special mode
    sd.write_block(0, build_enter_pattern(identifier))
    sd.write_block(0, build_enter_pattern(identifier))  # duplicate
    sd.write_block(0, build_leave_pattern(identifier))

    # Enter for read
    sd.write_block(0, build_enter_pattern(identifier))
    header = sd.read_block(5)

    # Leave
    sd.write_block(0, build_enter_pattern(identifier))
    sd.write_block(0, build_leave_pattern(identifier))

    return parse_header(header)
```

### To Authenticate
```python
def authenticate(sd, password, identifier, scramble_key):
    encoded = encode_password(password, scramble_key)

    # Session 1: Send password
    enter_mode(sd, identifier)
    sd.write_block(6, encoded)  # LBA 6 = auth
    leave_mode(sd, identifier)

    # Session 2: Check result
    enter_mode(sd, identifier)
    header = sd.read_block(5)
    leave_mode(sd, identifier)

    return header[0x49] == 0x00  # 0x00 = success
```

### Minimum Commands per Auth Attempt

```
Enter:   2 × CMD24 (enter pattern duplicated)
         1 × CMD24 (leave pattern)
Write:   1 × CMD24 to LBA 6 (encoded password)
Leave:   1 × CMD24 (enter) + 1 × CMD24 (leave)
Read:    1 × CMD24 (enter) + 1 × CMD17 (read LBA 5) + 2 × CMD24 (leave)
─────────────────────────────────────────────────────
Total:   9 × CMD24 + 1 × CMD17 = 10 SD commands per attempt
```

At ~100μs per command: **~1ms per attempt = 1000 attempts/second** theoretical maximum.

## X-Mask PRO Analysis

**Confirmed from `Saleae_traces_XMASK_PRO/` captures: X-Mask PRO uses IDENTICAL protocol!**

### Protocol Equivalence (Verified)

| Feature | X-Mask | X-Mask PRO |
|---------|--------|------------|
| Command interface | CMD17/CMD24 at LBAs | CMD17/CMD24 at LBAs |
| Enter/Leave | LBA 0 | LBA 0 |
| Status read | LBA 5 | LBA 5 |
| Auth | LBA 6 | LBA 6 |
| Remove password | LBA 7 | LBA 7 |
| Set password | LBA 8/9 | LBA 8/9 |
| TempUnlock | LBA 10 (0x0A) | LBA 10 (0x0A) |
| Identifier | Same 8-byte format | Same 8-byte format |
| Buffer format | Identical | Identical |

### Evidence from PRO Traces

**`enable_password_"P4ssw0rd!".csv`:**
- Line 69: CMD24 to LBA 9 with encoded password (SetKey)
- Line 144: CMD24 to LBA 8 with encoded password (SetKey alt)

**`temporary_disable_mask.csv`:**
- Line 288: CMD24 to LBA 6 (Authentication)
- Line 412: CMD24 to LBA 0x0A (TempUnlock)

**`permanently_disable_mask_mode.csv`:**
- Line 68: CMD24 to LBA 6 (Authentication)
- Line 192: CMD24 to LBA 7 (ResetKey/RemovePassword)

### PRO Header Format

From LBA 5 reads in PRO traces:
```
Offset 0x00-0x02:  Magic "SI0" or "RI0" or "SH "
Offset 0x03-0x0B:  Model "ET1289B0A" (vs "ET1288" on non-PRO)
Offset 0x58-0x5F:  Model string "FLXmD" or "FLXH"
```

### Security Implications

Despite marketing claims, both X-Mask and X-Mask PRO:
- Use identical wire protocol (LBA-based dispatch)
- Have same authentication flow
- Share identical security weaknesses:
  - No brute-force lockout
  - Public scramble key in header
  - Transport-only encoding

The "PRO" designation appears to be marketing only - **no protocol-level security improvements observed**.
