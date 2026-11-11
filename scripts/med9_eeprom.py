"""EEPROM operations for supported MED9 layouts."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Block:
    name: str
    start: int
    end: int  # inclusive; checksum follows in two big-endian bytes


# Recovered from the EAX/EDX/ECX arguments to 0x45A230 in 0x45B540.
BASE_BLOCKS = (
    Block("FD", 0x000, 0x03D),
    Block("IMMO1", 0x040, 0x05D),
    Block("IMMO2", 0x060, 0x07D),
    Block("IMMO3", 0x080, 0x0BD),
    Block("IMMO4", 0x0C0, 0x0FD),
    Block("HW1", 0x100, 0x11D),
    Block("FDCUST", 0x120, 0x13D),
    Block("SGID", 0x140, 0x15D),
    Block("DVE", 0x160, 0x17D),
    Block("TESTER1", 0x180, 0x19D),
    Block("TESTER2", 0x1A0, 0x1BD),
    Block("CALIB1", 0x1C0, 0x1DD),
    Block("CALIB2", 0x1E0, 0x1FD),
    Block("DFPMEEP", 0x200, 0x25D),
    Block("PRGID", 0x260, 0x27D),
    Block("PRG", 0x280, 0x29D),
    Block("PRG2", 0x2A0, 0x2BD),
    Block("VER", 0x2C0, 0x2DD),
    Block("IUMPR", 0x400, 0x4FB),
    Block("WVD", 0x600, 0x61D),
    Block("DFPMEEP5", 0x620, 0x71C),
)


def _check_size(data: bytes | bytearray) -> None:
    if len(data) not in (0x800, 0x1000):
        raise ValueError("Expected a 2 KiB (0x800) or 4 KiB (0x1000) EEPROM image")


def checksum_blocks(size: int) -> tuple[Block, ...]:
    """The tool checks 21 blocks; only for 4 KiB it also checks +0x800 copies."""
    if size not in (0x800, 0x1000):
        raise ValueError("Expected size 0x800 or 0x1000")
    if size == 0x800:
        return BASE_BLOCKS
    return BASE_BLOCKS + tuple(
        Block(b.name + " (mirror)", b.start + 0x800, b.end + 0x800)
        for b in BASE_BLOCKS
    )


def med9_checksum(data: bytes | bytearray, start: int, end: int) -> int:
    """0x45A230: 0xFFFF minus sum of bytes in [start, end], inclusive.

    This is an additive complement, not a polynomial CRC. The original keeps
    the sum in a signed 32-bit value. Every recovered block is short enough
    that the result is nonnegative and fits in 16 bits, even with all 0xFF.
    Reject unsupported long ranges rather than inventing a wrap convention.
    """
    if not 0 <= start <= end < len(data):
        raise ValueError("Invalid inclusive checksum range")
    value = 0xFFFF - sum(data[start:end + 1])
    if value < 0:
        raise ValueError("Range exceeds the recovered checksum's 16-bit domain")
    return value


def verify_checksums(data: bytes | bytearray) -> list[dict]:
    """Return each block's stored/calculated checksum and validity."""
    _check_size(data)
    result = []
    for block in checksum_blocks(len(data)):
        offset = block.end + 1
        stored = int.from_bytes(data[offset:offset + 2], "big")
        expected = med9_checksum(data, block.start, block.end)
        result.append({
            "block": block.name,
            "start": block.start,
            "end": block.end,
            "checksum_offset": offset,
            "stored": stored,
            "expected": expected,
            "valid": stored == expected,
        })
    return result


def repair_checksums(data: bytes | bytearray) -> bytes:
    """Reproduce the checksum button's EEPROM changes (0x45B540)."""
    _check_size(data)
    result = bytearray(data)
    for block in checksum_blocks(len(result)):
        value = med9_checksum(result, block.start, block.end)
        result[block.end + 1:block.end + 3] = value.to_bytes(2, "big")
    return bytes(result)


def immo_off_transform(data: bytes | bytearray) -> bytes:
    """Reproduce the memory-transform portion of 0x45C150 (before Click).

    XOR offset 0x59 by 3; copy the entire 0x20-byte block at 0x40 to 0x60,
    0x840, and 0x860. The original writes the latter copies in its global
    buffer even for a 2 KiB input, but those bytes are outside the saved file.
    Only in-file copies are returned here. This fragment does not fix checksums;
    the full original handler subsequently invokes Button3.Click to do that.
    It cannot determine whether an arbitrary input is already immo-off.
    """
    _check_size(data)
    result = bytearray(data)
    result[0x59] ^= 0x03
    source = bytes(result[0x40:0x60])
    for destination in (0x60, 0x840, 0x860):
        if destination + 0x20 <= len(result):
            result[destination:destination + 0x20] = source
    return bytes(result)


def immo_off(data: bytes | bytearray) -> bytes:
    """Reproduce the original immo-off handler's resulting EEPROM bytes.

    The original invokes Button3.Click via Delphi dynamic method -21 after
    transforming the EEPROM. Its OnClick handler, 0x45B540, repairs checksums.
    Same toggle semantics as immo_off_transform; do not apply repeatedly
    expecting a guaranteed off state. ECU operation is not hardware-validated.
    """
    return repair_checksums(immo_off_transform(data))
