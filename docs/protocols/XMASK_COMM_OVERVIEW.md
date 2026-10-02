# X-Mask PRO Communication Protocol Overview

## Host ↔ SD Card Communication Flow

### Transport Mapping

```
Host Application
  │
  ├─ Native SD ──────────► CMD56 Write/Read directly
  │
  └─ USB (UT33x) ───────► SCSI passthrough (opcode 0xF8)
                              ├─ sub 0x32 → CMD56 Write
                              ├─ sub 0x31 → CMD56 Read
                              ├─ Cmd25    → CMD25 (Write Multiple Block)
                              └─ Cmd18    → CMD18 (Read Multiple Block)
```

All data transfers use 512-byte (one sector) buffers.

### Atomic Operation Pattern

Every security operation follows the same 3-step pattern within one "session":

```
┌──────────────────────────────────────────────────────────┐
│  Step 1: ENTER SPECIAL MODE 2                            │
│  ├─ Host builds 512B enter pattern (CreateMode2Enter*)   │
│  └─ Host sends CMD56 Write                               │
│                                                          │
│  Step 2: COMMAND (one of)                                │
│  ├─ Write: Host builds encoded 512B → CMD25 (1 sector)  │
│  └─ Read:  Host reads 512B ← CMD18 (1 sector)           │
│                                                          │
│  Step 3: LEAVE SPECIAL MODE 2                            │
│  ├─ Host sends CMD56 Write (enter pattern again)         │
│  └─ Host sends CMD56 Write (leave pattern)               │
└──────────────────────────────────────────────────────────┘
```

Note: Leave always sends **two** CMD56 Writes back-to-back (an enter pattern then a leave pattern).

### Concrete Command Sequences

**Authentication (verify password):**
```
Host                              SD Card
 │                                   │
 │ ── CMD56 Write [Enter, func=2] ──►│  EnterSpecialMode2
 │ ── CMD25 Write [Encoded pwd] ────►│  WriteEncodePattern(0x06)
 │ ── CMD56 Write [Enter pattern] ──►│  LeaveSpecialMode2 (step 1)
 │ ── CMD56 Write [Leave pattern] ──►│  LeaveSpecialMode2 (step 2)
 │                                   │
 │ ── CMD56 Write [Enter, func=2] ──►│  EnterSpecialMode2
 │ ◄── CMD18 Read [512B header] ──── │  ReadHeader(0x05) → check offset 0x49
 │ ── CMD56 Write [Enter pattern] ──►│  LeaveSpecialMode2 (step 1)
 │ ── CMD56 Write [Leave pattern] ──►│  LeaveSpecialMode2 (step 2)
```

The host makes **two separate sessions**: first to send the encoded password (func 0x06), then to read back the result (func 0x05). Each session has its own Enter/Leave cycle.

**Set Password:**
```
Session 1: ReadHeader (func 0x05)     → read current status
Session 2: SetKey (func 0x08)         → write new encoded password
```

**Remove Password:**
```
Session 1: CertificationKey (func 0x06) → authenticate
Session 2: ReadHeader (func 0x05)        → verify auth succeeded
Session 3: ResetKey (func 0x07)          → remove password
```

**Temporary Unlock:**
```
Session 1: CertificationKey (func 0x06) → authenticate
Session 2: ReadHeader (func 0x05)        → verify auth succeeded
Session 3: TempUnlock (func 0x0A)        → unlock partition
```

---

## Secrets and Keys

| Secret              | Origin        | Where Stored            | Auth Required? | Role                           |
|---------------------|---------------|-------------------------|----------------|--------------------------------|
| **Identifier**      | Card          | Header (8 bytes)        | No             | Card identity, used in all CMD56 patterns |
| **Scramble key**    | Card          | Header offset 0xB8+     | No             | Seed component for CreateEncodePattern PRNG |
| **User password**   | User          | Not stored on host      | N/A            | Authenticates to card          |
| **XOR key**         | Host PRNG     | Transmitted at buf[0x149]| N/A            | Single-byte mask for Layer 1   |
| **PRNG seed**       | Host (time)   | Not transmitted          | N/A            | Seeds Mersenne Twister for Layer 2 |
| **DEADBEEF magic**  | Hardcoded     | buf[0x10C-0x10F]        | N/A            | Required for mode=3 enter      |

**Attacker-accessible without authentication:**
- Identifier (read via CMD56 func 0x05)
- Scramble key (read via CMD56 func 0x05, header offset 0xB8)
- Security mode flags (header offsets 0x1C0-0x1C2)

**Attacker-controlled:**
- PRNG seed (derived from `GetLocalTime()` on host — attacker chooses any value)
- XOR key (output of attacker-seeded PRNG)

**Only unknown to attacker:**
- User password

---

## Hard Requirements (Execution Order)

### To authenticate with a password:

```
1. READ IDENTIFIER           [No auth]
   └─ CMD56 func=0x05, extract 8 bytes from header
   └─ REQUIRED: all subsequent commands embed this identifier

2. READ SCRAMBLE KEY          [No auth]
   └─ Same CMD56 func=0x05 response, offset 0xB8
   └─ REQUIRED: needed to construct CreateEncodePattern seed

3. BUILD ENTER PATTERN        [Host-side only]
   ├─ identifier[0..7] → offset 0x000
   ├─ identifier[7..0] → offset 0x0F8 (reversed)
   ├─ 0x02 → offset 0x100 (command type)
   ├─ 0x01 → offset 0x101
   ├─ func code → offset 0x108
   └─ DEADBEEF → offset 0x10C (if security mode = 3)

4. ENTER SPECIAL MODE 2       [CMD56 Write]
   └─ Send 512B enter pattern to card

5. BUILD ENCODED PASSWORD     [Host-side only]
   ├─ Choose PRNG seed (any 32-bit value — attacker-controlled)
   ├─ XOR password with 32-bit Mersenne Twister outputs (128 iterations)
   ├─ Apply CBitArray bit reordering
   ├─ Compute 16-bit checksum → offset 0x1FE-0x1FF
   └─ REQUIRED: card reverses this exact encoding to verify

6. WRITE ENCODED PATTERN      [CMD25, 1 sector]
   └─ Send 512B encoded password buffer

7. LEAVE SPECIAL MODE 2       [CMD56 Write × 2]
   ├─ Send enter pattern (identifier normal)
   └─ Send leave pattern (identifier positions swapped)

8. READ RESULT                [New session: Enter → CMD18 → Leave]
   └─ Header offset 0x49 = authentication result
```

### Minimum SD commands for one authentication attempt:

```
CMD56 Write  ←  Enter (for password write)
CMD25 Write  ←  Encoded password
CMD56 Write  ←  Leave step 1
CMD56 Write  ←  Leave step 2
CMD56 Write  ←  Enter (for result read)
CMD18 Read   →  Response header
CMD56 Write  ←  Leave step 1
CMD56 Write  ←  Leave step 2
─────────────────────────────────
Total: 6 × CMD56 Write + 1 × CMD25 + 1 × CMD18 = 8 SD commands
```

---

## Encoding Layers Summary

```
         User Password (plaintext)
              │
              ▼
┌─────────────────────────────┐
│ Layer 1: Single-byte XOR    │  CreateSDKeyEnterPattern (0x0758c0)
│ key = MT19937(time_seed)    │  Key range: 1-254
│ key sent at buf[0x149]      │  ← key travels WITH ciphertext
└─────────────────────────────┘
              │                   Used only for Enter pattern (CMD56)
              ▼
┌─────────────────────────────┐
│ Layer 2: 32-bit PRNG XOR    │  CreateEncodePattern (0x06e810)
│ + CBitArray bit reorder     │
│ seed = scramble_key | time  │  ← scramble_key is public
│ 128 × 32-bit MT outputs    │  ← time is attacker-controlled
│ + 16-bit checksum           │
└─────────────────────────────┘
              │                   Used for data commands (CMD25)
              ▼
         Encoded buffer → SD card
```

Both layers are fully reversible by anyone holding the card (scramble key is public, PRNG seed is host-chosen).
