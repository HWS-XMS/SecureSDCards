#!/usr/bin/env python3
"""
Saleae Logic 2 SDIO CSV Parser for X-MASK Protocol Analysis.

Usage:
    python saleae_parser.py <trace.csv> [options]

Options:
    --cmd         Show CMD/RESP events
    --data        Show DATA events (default)
    --xmask       Show X-MASK summary only
    --serial XX   Serial for decoding (default: 69668301)
    --all         Show all event types
"""

import argparse
import csv
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.table import Table

from xmask_decode import (
    hex_to_bytes, parse_header, decode_auth_buffer, get_lba_name,
    parse_mode_buffer, LBA_HEADER, LBA_AUTH, LBA_REMOVE_PW, LBA_SET_PW,
    LBA_SET_PW_ALT, LBA_TEMP_UNLOCK, LBA_MODE
)


@dataclass
class Event:
    timestamp: float
    duration: float
    event_type: str  # CMD, RESP, DATA


@dataclass
class CmdEvent(Event):
    direction: bool  # True=host->card
    cmd: int = 0
    arg: int = 0
    crc: int = 0
    passed: bool = True


@dataclass
class RespEvent(Event):
    cmd: int = 0
    arg: int = 0
    crc: int = 0
    passed: bool = True


@dataclass
class DataEvent(Event):
    write: bool = False
    lba: int = 0
    data: bytes = b''
    crc16: int = 0
    parsed: dict = field(default_factory=dict)
    preceding_header: Optional['DataEvent'] = None


def parse_int(val: str) -> int:
    """Parse int from hex or decimal string."""
    if not val:
        return 0
    val = val.strip()
    if val.startswith('0x'):
        return int(val, 16)
    return int(val) if val else 0


def parse_csv(path: str) -> List[Event]:
    """Parse Saleae CSV into Event objects."""
    events = []

    with open(path, 'r') as f:
        reader = csv.DictReader(f)

        for row in reader:
            event_type = row.get('type', '').strip()
            if not event_type:
                continue

            try:
                timestamp = float(row.get('start_time', 0))
                duration = float(row.get('duration', 0))
            except ValueError:
                continue

            if event_type == 'CMD':
                direction = row.get('DIR', 'true').lower() == 'true'
                cmd = parse_int(row.get('CMD', '0'))
                arg = parse_int(row.get('ARG', '0'))
                crc = parse_int(row.get('CRC', '0'))
                passed = row.get('PASS', 'true').lower() == 'true'

                events.append(CmdEvent(
                    timestamp=timestamp,
                    duration=duration,
                    event_type='CMD',
                    direction=direction,
                    cmd=cmd,
                    arg=arg,
                    crc=crc,
                    passed=passed
                ))

            elif event_type == 'RESP':
                cmd = parse_int(row.get('CMD', '0'))
                arg = parse_int(row.get('ARG', '0'))
                crc = parse_int(row.get('CRC', '0'))
                passed = row.get('PASS', 'true').lower() == 'true'

                events.append(RespEvent(
                    timestamp=timestamp,
                    duration=duration,
                    event_type='RESP',
                    cmd=cmd,
                    arg=arg,
                    crc=crc,
                    passed=passed
                ))

            elif event_type == 'DATA':
                write = row.get('WRITE', 'false').lower() == 'true'
                addr_str = row.get('ADDR', '0')
                data_str = row.get('DATA', '')
                crc16_str = row.get('CRC16', '0')

                lba = parse_int(addr_str)
                try:
                    data = hex_to_bytes(data_str) if data_str else b''
                except ValueError:
                    data = b''
                crc16 = parse_int(crc16_str)

                events.append(DataEvent(
                    timestamp=timestamp,
                    duration=duration,
                    event_type='DATA',
                    write=write,
                    lba=lba,
                    data=data,
                    crc16=crc16
                ))

    return events


def correlate_events(events: List[Event], serial: bytes) -> List[Event]:
    """For each DATA write to LBA 6-10, find preceding LBA 5 read and parse."""
    last_header: Optional[DataEvent] = None
    last_header_parsed: Optional[dict] = None

    for event in events:
        if not isinstance(event, DataEvent):
            continue

        # Parse header reads
        if event.lba == LBA_HEADER and not event.write:
            parsed = parse_header(event.data)
            if parsed.get('index_a', 0) != 0:  # Valid header (not zeros)
                last_header = event
                last_header_parsed = parsed
            event.parsed = parsed

        # Parse mode buffer writes
        elif event.lba == LBA_MODE and event.write:
            event.parsed = parse_mode_buffer(event.data)

        # Parse auth buffer writes
        elif event.lba in (LBA_AUTH, LBA_REMOVE_PW, LBA_SET_PW, LBA_SET_PW_ALT, LBA_TEMP_UNLOCK) and event.write:
            event.preceding_header = last_header
            if last_header_parsed:
                scramble_key = last_header_parsed.get('scramble_key', b'\x00' * 8)
                decoded = decode_auth_buffer(event.data, scramble_key, serial)
                decoded['scramble_key'] = scramble_key
                event.parsed = decoded
            else:
                event.parsed = {'error': 'No preceding header'}

    return events


def render_cmd_table(events: List[Event], console: Console):
    """Rich table: Time | CMD | ARG | CRC | Pass"""
    table = Table(title="CMD/RESP Events")
    table.add_column("Time", style="cyan", no_wrap=True)
    table.add_column("Type", style="magenta")
    table.add_column("DIR")
    table.add_column("CMD", style="green")
    table.add_column("ARG", style="yellow")
    table.add_column("CRC")
    table.add_column("Pass", style="bold")

    for event in events:
        if isinstance(event, CmdEvent):
            direction = "H->C" if event.direction else "C->H"
            passed = "[green]YES[/green]" if event.passed else "[red]NO[/red]"
            table.add_row(
                f"{event.timestamp:.6f}",
                "CMD",
                direction,
                f"0x{event.cmd:02X}",
                f"0x{event.arg:08X}",
                f"0x{event.crc:02X}",
                passed
            )
        elif isinstance(event, RespEvent):
            passed = "[green]YES[/green]" if event.passed else "[red]NO[/red]"
            table.add_row(
                f"{event.timestamp:.6f}",
                "RESP",
                "C->H",
                f"0x{event.cmd:02X}",
                f"0x{event.arg:08X}",
                f"0x{event.crc:02X}",
                passed
            )

    console.print(table)


def render_data_table(events: List[Event], console: Console):
    """Rich table: Time | LBA | R/W | Size | Parsed Info"""
    table = Table(title="DATA Events")
    table.add_column("Time", style="cyan", no_wrap=True)
    table.add_column("LBA", style="magenta")
    table.add_column("R/W", style="green")
    table.add_column("Size", style="yellow")
    table.add_column("Info", no_wrap=False)

    for event in events:
        if not isinstance(event, DataEvent):
            continue

        rw = "[red]WRITE[/red]" if event.write else "[green]READ[/green]"
        lba_name = get_lba_name(event.lba)

        info = ""
        parsed = event.parsed

        if event.lba == LBA_HEADER and not event.write:
            if parsed.get('index_a', 0) == 0:
                info = "[dim]zeros header[/dim]"
            else:
                key = parsed.get('scramble_key', b'')
                key_hex = key.hex() if key else '?'
                idx_a = parsed.get('index_a', 0)
                idx_b = parsed.get('index_b', 0)
                status = parsed.get('status_1', 0)
                info = f"HDR: idx={idx_a:02X}/{idx_b:02X} key={key_hex[:16]}... st=0x{status:02X}"

        elif event.lba == LBA_MODE and event.write:
            mode_type = parsed.get('type', 'UNKNOWN')
            ident = parsed.get('identifier', '')
            info = f"MODE: {mode_type}" + (f" ({ident})" if ident else "")

        elif event.lba in (LBA_AUTH, LBA_REMOVE_PW, LBA_SET_PW, LBA_SET_PW_ALT, LBA_TEMP_UNLOCK) and event.write:
            if parsed.get('valid'):
                ms = parsed.get('ms_value', '?')
                info = f"[green]{lba_name}: dec=OK ms={ms}[/green]"
            else:
                key = parsed.get('scramble_key', b'')
                key_hex = key.hex()[:16] if key else '?'
                err = parsed.get('error', 'FAIL')
                info = f"[red]{lba_name}: dec=FAIL ({err[:20]})[/red]"

        else:
            info = f"{lba_name}: {len(event.data)}B"

        table.add_row(
            f"{event.timestamp:.6f}",
            f"{event.lba} ({lba_name})",
            rw,
            str(len(event.data)),
            info
        )

    console.print(table)


def render_xmask_summary(events: List[Event], console: Console):
    """Rich table: Time | Operation | Scramble Key | Decoded | Valid"""
    table = Table(title="X-MASK Summary")
    table.add_column("Time", style="cyan", no_wrap=True)
    table.add_column("Operation", style="magenta")
    table.add_column("Scramble Key", style="yellow")
    table.add_column("Decoded", style="green")
    table.add_column("Valid", style="bold")

    for event in events:
        if not isinstance(event, DataEvent):
            continue
        if event.lba not in (LBA_AUTH, LBA_REMOVE_PW, LBA_SET_PW, LBA_SET_PW_ALT, LBA_TEMP_UNLOCK):
            continue
        if not event.write:
            continue

        parsed = event.parsed
        lba_name = get_lba_name(event.lba)

        key = parsed.get('scramble_key', b'')
        key_hex = key.hex() if key else '???'

        if parsed.get('valid'):
            ms = parsed.get('ms_value', '?')
            decoded = f"ms={ms}"
            valid = "[green]YES[/green]"
        else:
            decoded = "???"
            valid = "[red]NO[/red]"

        table.add_row(
            f"{event.timestamp:.6f}",
            lba_name,
            key_hex,
            decoded,
            valid
        )

    console.print(table)


def main():
    parser = argparse.ArgumentParser(description='Parse Saleae SDIO traces for X-MASK protocol')
    parser.add_argument('trace', help='Path to CSV trace file')
    parser.add_argument('--cmd', action='store_true', help='Show CMD/RESP events')
    parser.add_argument('--data', action='store_true', help='Show DATA events')
    parser.add_argument('--xmask', action='store_true', help='Show X-MASK summary only')
    parser.add_argument('--all', action='store_true', help='Show all event types')
    parser.add_argument('--serial', default='69668301', help='Serial for decoding (default: 69668301)')

    args = parser.parse_args()

    if not Path(args.trace).exists():
        print(f"Error: File not found: {args.trace}", file=sys.stderr)
        sys.exit(1)

    serial = args.serial.encode('ascii')

    console = Console()
    console.print(f"[bold]Parsing:[/bold] {args.trace}")

    events = parse_csv(args.trace)
    console.print(f"[dim]Loaded {len(events)} events[/dim]")

    events = correlate_events(events, serial)

    # Default to --data if no options specified
    if not any([args.cmd, args.data, args.xmask, args.all]):
        args.data = True

    if args.all or args.cmd:
        render_cmd_table(events, console)

    if args.all or args.data:
        render_data_table(events, console)

    if args.all or args.xmask:
        render_xmask_summary(events, console)


if __name__ == '__main__':
    main()
