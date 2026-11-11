"""Detect supported MED9 flash layouts and verify or repair checksums."""
from dataclasses import dataclass
import struct


FLASH_SIZE = 0x200000
KEY_OFFSET = 0x80300
KEY_SIZE = 0x86
REGION_OFFSET = 0x81768
REGION_SIZE = 5 * 20
BLOB_OFFSETS = (0x7FF00, 0x9FF00, 0x1BFF00, 0x1FFF00)
T1_OFFSET = 0xA0000
T2_SEARCH = (0x1C2000, 0x1C4000)
MAX_TABLE_ROWS = 128
SIGNED_REGIONS = (
    (0x404000, 0x47FEFF, 0x47FF00),
    (0x20000, 0x7FEFF, 0x7FF00),
    (0x80000, 0x9FEFF, 0x9FF00),
    (0xA0000, 0x1BFEFF, 0x1BFF00),
    (0x1C2000, 0x1FFEFF, 0x1FFF00),
)


@dataclass(frozen=True)
class ChecksumRow:
    table: str
    offset: int
    start: int
    end: int
    expected: int

    @property
    def file_range(self):
        if 0x400000 <= self.start <= self.end < 0x600000:
            return self.start - 0x400000, self.end - 0x400000
        return self.start, self.end


@dataclass(frozen=True)
class FlashProfile:
    mode: str  # crc-only, signed, unknown
    reason: str
    rows: tuple = ()

    @property
    def label(self):
        return {
            "crc-only": "MED9 CRC only (no blob signing)",
            "signed": "MED9 hash/blob signing",
            "unknown": "Unrecognized flash integrity layout",
        }[self.mode]


def _erased(block):
    # Require the actual erased state, not arbitrary invalid key bytes.
    return bool(block) and all(value == 0xFF for value in block)


def _flash_range(start, end):
    if 0x400000 <= start <= end < 0x600000:
        start -= 0x400000
        end -= 0x400000
    if not 0 <= start < end < FLASH_SIZE:
        return None
    if start % 2 or end % 2 != 1:
        return None
    return start, end


def _table(data, offset, name):
    """Read a complete, bounded sequence of plausible complemented rows.

    A bad complement inside a plausible row is an error, not a terminator.
    That prevents silently accepting only a prefix of a damaged table.
    """
    rows = []
    for index in range(MAX_TABLE_ROWS):
        position = offset + index * 16
        if position + 16 > len(data):
            raise ValueError("%s checksum table extends beyond the image" % name)
        start, end, expected, complement = struct.unpack_from(">4I", data, position)
        mapped = _flash_range(start, end)
        if mapped is None:
            if complement == (~expected & 0xFFFFFFFF):
                raise ValueError("%s row @0x%X has an unsupported address range" % (name, position))
            if not rows:
                raise ValueError("%s checksum table not found" % name)
            return tuple(rows)
        if complement != (~expected & 0xFFFFFFFF):
            raise ValueError("%s checksum row @0x%X has a broken complement" % (name, position))
        rows.append(ChecksumRow(name, position, start, end, expected))
    raise ValueError("%s checksum table has no terminator within the row limit" % name)


def _crc_tables(data):
    first = _table(data, T1_OFFSET, "T1")
    # The supported format begins with its header checksum, followed by the
    # first complete application block. Do not infer support from random rows.
    if len(first) < 2 or first[0].start != 0x20004 or first[1].start != 0x20000:
        raise ValueError("Unrecognized first checksum-table layout")
    if not any(row.start == 0xA0000 for row in first):
        raise ValueError("First checksum table is incomplete")
    if first[-1].file_range[1] != FLASH_SIZE - 1:
        raise ValueError("First checksum table does not reach the end of this layout")
    candidates = []
    for position in range(*T2_SEARCH, 16):
        start, end, expected, complement = struct.unpack_from(">4I", data, position)
        if (0x5C0000 <= start < 0x600000 and _flash_range(start, end) is not None
                and complement == (~expected & 0xFFFFFFFF)):
            candidates.append(position)
    if not candidates:
        raise ValueError("Second checksum table not found")
    # First row describes the immediately preceding header and ends directly
    # before the table. Later rows in that same table must not become seeds.
    headers = [position for position in candidates
               if struct.unpack_from(">I", data, position + 4)[0] - 0x400000 == position - 1]
    if len(headers) != 1:
        raise ValueError("Second checksum-table header is missing or ambiguous")
    second = _table(data, headers[0], "T2")
    if (len(second) < 3 or second[1].start != 0x5C2000
            or second[2].start != 0x5C2E00
            or second[-1].end not in (0x5EFFFF, 0x5FFFFF, 0x5FFEFF)):
        raise ValueError("Second checksum table is incomplete")
    return first + second


def detect_profile(data):
    """Distinguish the supported signer from an explicitly absent signer.

    Invalid/partly erased signing metadata remains unknown. Only an erased
    key, erased region table, erased blob slots and complete flash-only CRC
    tables admit checksum-only correction.
    """
    if len(data) != FLASH_SIZE:
        return FlashProfile("unknown", "Expected a 2 MiB flash image")
    bit_length = struct.unpack_from(">H", data, KEY_OFFSET)[0]
    modulus = int.from_bytes(data[KEY_OFFSET + 2:KEY_OFFSET + 0x82], "big")
    exponent = struct.unpack_from(">I", data, KEY_OFFSET + 0x82)[0]
    regions = [struct.unpack_from(">5I", data, REGION_OFFSET + i * 20)[:3]
               for i in range(5)]
    known_regions = tuple(regions) == SIGNED_REGIONS
    valid_key = (bit_length == 1024 and 1000 <= modulus.bit_length() <= 1024
                 and modulus % 2 == 1 and exponent == 3)
    if known_regions and valid_key:
        return FlashProfile("signed", "Recognized signing key and five-region descriptor table")
    key_erased = _erased(data[KEY_OFFSET:KEY_OFFSET + KEY_SIZE])
    regions_erased = _erased(data[REGION_OFFSET:REGION_OFFSET + REGION_SIZE])
    blobs_erased = all(_erased(data[off:off + 128]) for off in BLOB_OFFSETS)
    if not (key_erased and regions_erased and blobs_erased):
        return FlashProfile("unknown", "Signing metadata is present, damaged or unsupported")
    try:
        rows = _crc_tables(data)
    except ValueError as exc:
        return FlashProfile("unknown", str(exc))
    return FlashProfile("crc-only", "Signing areas erased; complete flash checksum tables found", rows)


def word_sum(data, start, end):
    """Sum big-endian u16 words over the inclusive range, modulo 2**32."""
    return sum(value[0] for value in struct.iter_unpack(">H", data[start:end + 1])) & 0xFFFFFFFF


def verify_checksums(data, log=lambda message: None):
    profile = detect_profile(data)
    if profile.mode != "crc-only":
        raise ValueError("CRC-only verification unavailable: " + profile.reason)
    results = []
    for row in profile.rows:
        actual = word_sum(data, *row.file_range)
        result = {"table": row.table, "offset": row.offset,
                  "start": row.start, "end": row.end,
                  "stored": row.expected, "expected": actual,
                  "valid": row.expected == actual}
        results.append(result)
        if not result["valid"]:
            log("  [FAIL] %s row @0x%X: %08X, expected %08X"
                % (row.table, row.offset, row.expected, actual))
    valid = sum(result["valid"] for result in results)
    log("  CRC/checksum rows: %d/%d valid" % (valid, len(results)))
    return results


def repair_checksums(data, log=lambda message: None):
    profile = detect_profile(data)
    if profile.mode != "crc-only":
        raise ValueError("CRC-only correction unavailable: " + profile.reason)
    result = bytearray(data)
    patched = 0
    for row in profile.rows:
        value = word_sum(result, *row.file_range)
        if value != row.expected:
            struct.pack_into(">II", result, row.offset + 8, value, ~value & 0xFFFFFFFF)
            patched += 1
    # Every admitted row already has a valid complement; replacing a value
    # and its complement preserves its u16 word sum, including self-coverage.
    if not all(row["valid"] for row in verify_checksums(result)):
        raise ValueError("CRC correction self-check failed")
    log("  [FIX] %d checksum row(s) repaired; no signing performed" % patched)
    return bytes(result)
