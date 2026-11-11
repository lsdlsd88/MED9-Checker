# -*- coding: utf-8 -*-
# MED9 flash and EEPROM checker.
# GUI: separate FLASH / MPC drop zones (a combined dump dropped into either zone fills both).
# CLI: python med9_checker.py <flash.FLS> [mpc.MPC]
import sys, os, struct
from pathlib import Path
from tempfile import NamedTemporaryFile

# ---------------- engine ----------------

# real blob engine (transpiled from the ECU disassembly) lives next to this script
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
_scripts_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts")
if os.path.isdir(_scripts_dir):
    sys.path.insert(0, _scripts_dir)
import med9_eeprom as eeprom
import med9_flash as flash
try:
    import med9_hash_gen as eng
except Exception:
    eng = None

SIZE_FLS, SIZE_MPC, SIZE_COMBINED, SIZE_EPR = 2097152, 524288, 2621440, 2048
SIZES_EPR = (SIZE_EPR, 4096)
APP_VERSION = "v0.1"


def browse_dump(askopenfilename, **options):
    """Open a dump picker and persist the selected directory for all pickers."""
    appdata = os.environ.get("LOCALAPPDATA")
    settings_dir = Path(appdata) / "MED9Checker" if appdata else Path.home() / ".med9-checker"
    settings = settings_dir / "last-folder.txt"
    launcher = sys.executable if getattr(sys, "frozen", False) else __file__
    initial_dir = Path(launcher).resolve().parent
    try:
        saved = Path(settings.read_text(encoding="utf-8"))
        if saved.is_absolute() and saved.is_dir():
            initial_dir = saved
    except (OSError, ValueError):
        pass

    selected = askopenfilename(initialdir=str(initial_dir), **options)
    if not selected:
        return selected

    temporary = None
    try:
        settings_dir.mkdir(parents=True, exist_ok=True)
        with NamedTemporaryFile(mode="w", encoding="utf-8", dir=settings_dir,
                                prefix="last-folder-", delete=False) as file:
            temporary = Path(file.name)
            file.write(str(Path(selected).absolute().parent))
        temporary.replace(settings)
    except OSError:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
    return selected


def parse_layout(size):
    if size == SIZE_COMBINED: return "combined"   # FLS(2M) + MPC(512K)
    if size == SIZE_FLS: return "fls"
    if size in (SIZE_MPC, SIZE_MPC + 0x200): return "mpc"
    if size in SIZES_EPR: return "epr"
    return "unknown"

def cstr(d, off, n=32):
    out = []
    for b in d[off:off+n]:
        out.append(chr(b) if 32 <= b < 127 else '.')
    return "".join(out)

def check_boot_page(log, data, chip="fls"):
    """boot page 0x1F00-0x2000: version u16 @pair+6, value/complement u32 pair @0x1FF8/0x1FFC."""
    log("[CHECK] boot page (%s) 0x1F00-0x2000" % chip)
    found = []
    for off in range(0x1F00, 0x1FFC, 4):
        a = struct.unpack_from(">I", data, off)[0]
        b = struct.unpack_from(">I", data, off + 4)[0]
        if a != 0xFFFFFFFF and a == (~b & 0xFFFFFFFF):
            found.append((off, a, b))
    if not found:
        log("  [FAIL] no value/~complement pair found in boot page")
        return None
    for off, a, b in found:
        ver = struct.unpack_from(">H", data, off - 0xA)[0]
        log("  pair @%04X: value=%08X  complement=%08X  (~ok)" % (off, a, b))
        log("  version u16 @%04X = %04X (%d) - must be >= 0x259 (601)" % (off - 0xA, ver, ver))
        if ver < 0x259:
            log("  [FAIL] version below 601 threshold!")
        else:
            log("  [OK] boot page complement consistent")
    return found

def epr_scan(data):
    """walk 2KB EPR: records [id][len][data..][crc16], crc = 0xFFFF-(id+len+sum(data)), stored twice."""
    recs = []
    o = 0
    n = len(data)
    while o <= n - 32:
        matched = None
        for size in (32, 64, 256):
            if o + size > n: continue
            idb, lenb = data[o], data[o+1]
            if idb == 0 and lenb == 0: continue
            if idb >= 0x40: continue
            s = (idb + lenb + sum(data[o+2:o+size-2])) & 0xFFFF
            crc = struct.unpack_from(">H", data, o+size-2)[0]
            if (0xFFFF - s) & 0xFFFF == crc:
                matched = (o, size, idb, lenb)
                break
        if matched:
            recs.append(matched)
            o += matched[1]
        else:
            o += 1
    return recs

def epr_verify(data):
    """verify pass over the record chain. Regions not covered by a crc-valid
    record are classified: erased space (all 0xFF/0x00) and non-record areas
    (extra [id][version] blocks - NOT decoded, never touched) are reported
    separately; record-shaped gaps flanked by valid records are stale records
    that epr_fix_gaps can repair. returns (records, bad, extra)."""
    recs = epr_scan(bytes(data))
    # the record chain uses ids 0x01..0x16 (observed across dumps); foreign
    # non-record areas carry other ids (e.g. 0x18, 0x26) and are never touched
    chain_ids = set(range(1, 0x17)) | set(idb for _, _, idb, _ in recs)
    covered = bytearray(len(data))
    anchors = sorted((off, off + size) for off, size, idb, lenb in recs)
    for a0, a1 in anchors:
        for i in range(a0, a1):
            covered[i] = 1
    def flanked(start, size):
        # file boundaries count as edges for the first/last record
        end = start + size
        if start == 0 and end == n:
            return False   # whole image is one gap -> refuse
        before = start == 0 or any(a1 == start for _, a1 in anchors)
        after = end == n or any(a0 == end for a0, _ in anchors)
        return before and after
    bad = []
    extra = []
    o = 0
    n = len(data)
    while o < n:
        if covered[o]:
            o += 1
            continue
        start = o
        while o < n and not covered[o]:
            o += 1
        size = o - start
        seg = data[start:o]
        if all(b in (0x00, 0xFF) for b in seg):
            continue   # erased space
        if (data[start] in chain_ids and size in (32, 64, 256)
                and flanked(start, size)):
            bad.append((start, size))
        else:
            extra.append((start, size))
    return recs, bad, extra

def epr_restamp(data, off, size, idb, lenb):
    """recompute and write the crc16 of the record frame at off"""
    crc = (0xFFFF - (idb + lenb + sum(data[off+2:off+size-2]))) & 0xFFFF
    struct.pack_into(">H", data, off+size-2, crc)

def epr_fix_gaps(data):
    """repair stale records: restamp the crc of each bad region found by
    epr_verify (record-shaped, flanked by valid records). returns list of
    (off, size, id, len) repaired."""
    recs, bad, extra = epr_verify(data)
    fixed = []
    for start, size in bad:
        idb, lenb = data[start], data[start+1]
        epr_restamp(data, start, size, idb, lenb)
        fixed.append((start, size, idb, lenb))
    return fixed

def epr_identity_records(data):
    """Known 64-byte IMMO3/4 records containing VIN / Immo ID / VIN.

    Two VINs sit at record +5 and +0x24, with a 14-byte Immo ID between
    them at +0x16. Restrict parsing to these fields so a text scan cannot
    mistake the Immo ID plus three VIN characters for another VIN.
    """
    return [record for record in epr_scan(bytes(data))
            if record[0] in (0x80, 0xC0, 0x880, 0x8C0)
            and record[1] == 64 and record[2] == 0x02]


def epr_find_vins(data):
    """Return real VIN fields and their containing checksum-valid records."""
    import re as _re
    out = []
    for roff, rsize, rid, rlen in epr_identity_records(data):
        for relative in (5, 0x24):
            off = roff + relative
            value = bytes(data[off:off + 17])
            if _re.fullmatch(rb"[A-HJ-NPR-Z][A-HJ-NPR-Z0-9]{16}", value):
                out.append((off, value.decode("ascii"), roff, rsize, rid, rlen))
    return out


def epr_find_immo_ids(data):
    """Return the 14-character Immo ID fields, without adjacent VIN bytes."""
    import re as _re
    out = []
    for roff, rsize, rid, rlen in epr_identity_records(data):
        off = roff + 0x16
        value = bytes(data[off:off + 14])
        if _re.fullmatch(rb"[A-Z0-9]{14}", value):
            out.append((off, value.decode("ascii"), roff, rsize, rid, rlen))
    return out


def epr_set_identity(data, vin, immo_id):
    """Apply one VIN and Immo ID to all identity copies, restamping records."""
    import re as _re
    if not _re.fullmatch(r"[A-HJ-NPR-Z][A-HJ-NPR-Z0-9]{16}", vin):
        raise ValueError("VIN must be 17 letters/numbers, without I, O or Q")
    if not _re.fullmatch(r"[A-Z0-9]{14}", immo_id):
        raise ValueError("Immo ID must be 14 letters/numbers")
    records = epr_identity_records(data)
    if len(data) not in SIZES_EPR or len(records) != 2 * (len(data) // 2048):
        raise ValueError("Identity records missing or invalid; verify/fix checksums first")
    result = bytearray(data)
    for off, size, rid, rlen in records:
        result[off + 5:off + 22] = vin.encode("ascii")
        result[off + 0x16:off + 0x24] = immo_id.encode("ascii")
        result[off + 0x24:off + 0x35] = vin.encode("ascii")
        epr_restamp(result, off, size, rid, rlen)
    data[:] = result
    return 2 * len(records), len(records)

def epr_set_vin(data, slot_off, new_vin, slots=None):
    """write a new 17-char VIN into the slot at slot_off (and into every other
    slot that held the same VIN - both storage copies), restamping each
    containing record. returns number of slots written"""
    if len(new_vin) != 17:
        return 0
    if slots is None:
        slots = epr_find_vins(data)
    old = None
    for off, vin, ro, rs, rid, rlen in slots:
        if off == slot_off:
            old = vin.encode()
            break
    if old is None:
        return 0
    b = new_vin.encode()
    n = 0
    touched = set()
    for off, vin, ro, rs, rid, rlen in slots:
        if vin.encode() != old:
            continue
        data[off:off+17] = b
        epr_restamp(data, ro, rs, rid, rlen)
        touched.add((ro, rs, rid, rlen))
        n += 1
    return n

def check_epr(log, data):
    log("[CHECK] EEPROM records (%d KB)" % (len(data) // 1024))
    recs, bad, extra = epr_verify(data)
    seen = {}
    for off, size, idb, lenb in recs:
        seen[idb] = seen.get(idb, 0) + 1
    log("  records: %d, distinct ids: %d, all crc valid" % (len(recs), len(seen)))
    dups = {k: v for k, v in seen.items() if v >= 2}
    log("  double-written ids: %d (redundancy ok)" % len(dups))
    known = {0x02: "VIN", 0x04: "HW part", 0x05: "SW part", 0x0A: "data", 0x0C: "data", 0x16: "table"}
    for off, size, idb, lenb in recs:
        if idb in known:
            log("    id 0x%02X @%04X %-8s data: %s" % (idb, off, known[idb], cstr(data, off+2, min(24, size-4))))
    if bad:
        log("  [WARN] %d stale record(s) - CRC mismatch (fixable)" % len(bad))
    if extra:
        log("  [INFO] %d non-record area(s) present (not decoded, left untouched)" % len(extra))
    checksums = eeprom.verify_checksums(data)
    mismatches = [row for row in checksums if not row["valid"]]
    for row in mismatches:
        log("  [WARN] %s @0x%03X: checksum %04X, expected %04X"
            % (row["block"], row["checksum_offset"], row["stored"], row["expected"]))
    if not mismatches:
        log("  [OK] all %d block checksums valid" % len(checksums))

    # VIN slots
    slots = epr_find_vins(data)
    if slots:
        log("  VIN slots:")
        for off, vin, ro, rs, rid, rlen in slots:
            log("    @0x%03X: %s" % (off, vin))

    # PRGID record (id 0x0B) - show raw fields, no interpretation
    for off, size, idb, lenb in epr_scan(data):
        if idb != 0x0B or size != 32:
            continue
        p = data[off+2:off+size-2]
        cpl_ok = p[19] == (~p[7] & 0xFF) and p[20] == (~p[8] & 0xFF)
        log("  PRGID (id 0x0B): %s  compl=%s" % (p.hex().upper(), "ok" if cpl_ok else "BAD"))
        break

    return recs

def check_identity(log, fls):
    log("[CHECK] identity strings")
    i = fls.find(b"0261S")
    if i >= 0:
        log("  build      : %s @%04X" % (cstr(fls, i, 10), i))
    i = fls.find(b"MED91/5/")
    if i >= 0:
        log("  ident      : %s" % cstr(fls, i-4, 56))
    i = fls.find(b"8J0907404")
    if i >= 0:
        log("  ECU partno : %s @%04X" % (cstr(fls, i, 12), i))
    i = fls.find(b"2.5l R5")
    if i >= 0:
        log("  engine     : %s" % cstr(fls, i, 20))

def check_faultclass(log, mpc):
    if len(mpc) < 0x1E6EC8 + 275:
        return
    log("[CHECK] fault-class table (mpc @0x1E6EC8, 275 entries)")
    t = mpc[0x1E6EC8:0x1E6EC8+275]
    hidden = t.count(0x00)
    log("  hidden (class 0): %d / 275   nonzero: %d / 275" % (hidden, 275 - hidden))
    log("  [INFO] class 0 = fault hidden from scan + no MIL (set to 0 to hide a fault)")
    cat = mpc[0x1E7202:0x1E7202+275*8]
    n601 = 0
    for k in range(275):
        rec = cat[k*8:(k+1)*8]
        if rec[0:2] == b"\x06\x01":
            n601 += 1
            log("  P0601 record #%d @0x%06X: %s" % (k+1, 0x1E7202 + k*8, rec.hex()))
    log("  DTC catalog: %d records, P0601 entries: %d" % (275, n601))

def check_blobs(log, fls, mpc, profile=None):
    """REAL verification: custom hash over each region vs the decoded blob (A^C mod n).
    Returns the verification results for the loaded regions."""
    if fls is None:
        return None
    profile = profile or flash.detect_profile(fls)
    log("[MODE] %s" % profile.label)
    if profile.mode == "crc-only":
        log("[CHECK] Flash CRC/checksums; this layout has no blob signing")
        rows = flash.verify_checksums(fls, log)
        bad = sum(not row["valid"] for row in rows)
        return [dict(idx="CRC", status="FAIL" if bad else "PASS",
                     note="%d/%d checksum rows wrong" % (bad, len(rows)))]
    if profile.mode == "unknown":
        log("[WARN] %s - automatic flash correction unavailable" % profile.reason)
        return [dict(idx="PROFILE", status="UNSUPPORTED", note=profile.reason)]
    if eng is None:
        log("[FAIL] Signing engine missing")
        return [dict(idx="ENGINE", status="UNAVAILABLE", note="Signing engine missing")]
    mpc = mpc[:0x80000] if mpc else None
    log("[CHECK] blob verification (A^C mod n == 0001 FF{8} 00 || hash(region) || free || 95x00)")
    bitlen, n, C = eng.read_key(fls)
    log("  key @0x80300: bitlen=0x%04X  n=%s...  C=%d" % (bitlen, n.to_bytes(128,'big')[:8].hex(), C))
    res = eng.verify_all(fls, mpc, log)
    bad = [r for r in res if r["status"] in ("STALE/MODIFIED", "FAIL")]
    if bad:
        log("  [FAIL] %d region(s) stale/modified -> 'Check & correct' re-signs with the chosen key" % len(bad))
    else:
        log("  [OK] all ECU-verified regions pass")
    r0 = next((r for r in res if r.get("idx") == 0), None)
    if r0 and r0["status"] == "FAIL" and not r0.get("shape", True):
        log("  [HINT] R0 blob does not even decode with this file's key -> the MPC file")
        log("         likely does NOT belong to this FLS (mixed read set). 'Check & correct'")
        log("         can still make the pair self-consistent (compat key + re-sign).")
    return res

def fix_blobs(log, fls_data, mpc_data):
    """Re-sign all regions with the compatibility key pair.
    Returns (new_fls, new_mpc, info)."""
    if eng is None:
        log("[FAIL] engine missing")
        return None, None, None
    if flash.detect_profile(fls_data).mode != "signed":
        log("[FAIL] Blob signing is unavailable for this flash layout")
        return None, None, None
    return eng.forge_all(fls_data, mpc_data[:0x80000] if mpc_data else None, log)

# ---------------- joint check / fix over a {chip: path} set ----------------

def run_checks(log, paths):
    """paths: dict chip -> file path ('fls', 'mpc', optionally 'epr').
    Returns (data, fixlist) or None."""
    data = {}
    for chip, p in paths.items():
        if not p or not os.path.isfile(p): continue
        with open(p, "rb") as f:
            data[chip] = f.read()
    # combined dump (same path in both zones): split into the two halves
    if data.get("fls") is not None and data.get("mpc") is not None and paths.get("fls") == paths.get("mpc") \
       and len(data["fls"]) == SIZE_COMBINED:
        data["fls"] = data["fls"][:SIZE_FLS]
        data["mpc"] = data["mpc"][0x200000:0x200000 + SIZE_MPC]
    fixlist = []
    fls = data.get("fls")
    mpc = data.get("mpc")
    epr = data.get("epr")
    profile = flash.detect_profile(fls) if fls is not None else None
    if fls is None and mpc is None and epr is None:
        log("[FAIL] nothing loaded")
        return None
    if fls is not None: log("FLASH : %s (%d bytes)" % (os.path.basename(paths['fls']), len(fls)))
    if mpc is not None: log("MPC   : %s (%d bytes)" % (os.path.basename(paths['mpc']), len(mpc)))
    if epr is not None: log("EEPROM: %s (%d bytes)" % (os.path.basename(paths['epr']), len(epr)))
    log("=" * 72)
    if epr is not None:
        check_epr(log, epr)
    if fls is not None:
        check_identity(log, fls)
        check_boot_page(log, fls, "fls")
    if mpc is not None:
        check_boot_page(log, mpc[:0x80000], "mpc")
    blobres = check_blobs(log, fls, mpc, profile)
    if mpc is not None:
        check_faultclass(log, mpc[:0x80000])
    # boot page fixables: canonical pair 0x1FF8/0x1FFC only
    for chip in ("fls", "mpc"):
        d = data.get(chip)
        if d is None or len(d) < 0x2000: continue
        if chip == "fls" and profile.mode == "unknown":
            continue
        a = struct.unpack_from(">I", d, 0x1FF8)[0]
        b = struct.unpack_from(">I", d, 0x1FFC)[0]
        if a != 0xFFFFFFFF and a != (~b & 0xFFFFFFFF):
            fixlist.append(("bootpage-complement", chip, 0x1FF8))
            log("[FAIL] %s: complement pair broken (value=%08X complement=%08X expected=%08X)"
                % (chip, a, b, (~a) & 0xFFFFFFFF))
        else:
            log("[OK] %s: boot page complement pair intact" % chip)
    if blobres is not None and any(r["status"] in ("STALE/MODIFIED", "FAIL") for r in blobres):
        if profile.mode == "crc-only":
            fixlist.append(("flash-crc", "fls", 0))
            log("[FAIL] Flash CRC/checksum correction required")
        elif profile.mode == "signed":
            fixlist.append(("blobs", "fls", 0))
            log("[FAIL] blob re-sign required")
    # EEPROM record chain integrity check (P0601-adjacent: a broken EEPROM
    # record chain could trigger boot-time faults, but the exact mechanism
    # is not fully decoded - BDM tuning works fine without touching the EEPROM)
    if epr is not None and len(epr) in SIZES_EPR:
        checksums = eeprom.verify_checksums(epr)
        bad = [row for row in checksums if not row["valid"]]
        if bad:
            log("[WARN] EEPROM: %d block checksum mismatch(es)" % len(bad))
            log("       -> use EEPROM tools > Fix CRCs, or verify the chip externally")
        else:
            log("[OK] EEPROM: all %d block checksums valid" % len(checksums))
    return data, fixlist

def apply_fixes_multi(log, paths, data, fixlist):
    """Fix and save per-chip outputs; originals untouched.
    combined input (same path for both chips) -> single _signed.bin output."""
    if not fixlist:
        log("[INFO] nothing to correct")
        return
    combined = bool(paths.get("fls")) and paths.get("fls") == paths.get("mpc")
    fls = bytearray(data["fls"]) if data.get("fls") else None
    mpc = bytearray(data["mpc"]) if data.get("mpc") else None
    do_blobs = any(f[0] == "blobs" for f in fixlist)
    do_crc = any(f[0] == "flash-crc" for f in fixlist)
    profile = flash.detect_profile(fls) if fls is not None else None
    if do_crc and (profile is None or profile.mode != "crc-only" or do_blobs):
        log("[FAIL] Flash does not support checksum-only correction - nothing saved")
        return
    if do_blobs:
        if fls is None or mpc is None:
            log("[FAIL] blob re-sign needs BOTH flash and MPC loaded")
            return
        nf, nm, info = fix_blobs(log, bytes(fls), bytes(mpc))
        if not info or not info.get("ok"):
            log("[FAIL] re-sign self-check failed - nothing saved")
            return
        fls, mpc = bytearray(nf), bytearray(nm)
    # boot page complements (canonical pair only)
    for chip, arr in (("fls", fls), ("mpc", mpc)):
        if arr is None: continue
        if not any(f[0] == "bootpage-complement" and f[1] == chip for f in fixlist):
            continue
        a = struct.unpack_from(">I", arr, 0x1FF8)[0]
        b = struct.unpack_from(">I", arr, 0x1FFC)[0]
        if a != 0xFFFFFFFF and a != (~b & 0xFFFFFFFF):
            struct.pack_into(">I", arr, 0x1FFC, (~a) & 0xFFFFFFFF)
            log("[FIX] %s boot page complement rewritten (0x%08X)" % (chip, (~a) & 0xFFFFFFFF))
    if profile is not None and profile.mode == "crc-only" and (
            do_crc or any(f[0] == "bootpage-complement" and f[1] == "fls" for f in fixlist)):
        try:
            fls = bytearray(flash.repair_checksums(fls, log))
        except ValueError as exc:
            log("[FAIL] %s - nothing saved" % exc)
            return
    # save: export BOTH formats (per-chip + combined) so any flasher workflow works
    touch_fls = do_blobs or do_crc or any(f[0] == "bootpage-complement" and f[1] == "fls" for f in fixlist)
    touch_mpc = do_blobs or any(f[0] == "bootpage-complement" and f[1] == "mpc" for f in fixlist)
    suffix = "_signed" if do_blobs else "_fixed"
    both = fls is not None and mpc is not None
    if touch_fls:
        out = os.path.splitext(paths["fls"])[0] + suffix + ".FLS"
        with open(out, "wb") as f:
            f.write(bytes(fls))
        log("[DONE] saved: %s (%d bytes, original untouched)" % (out, len(fls)))
    if touch_mpc:
        out = os.path.splitext(paths["mpc"])[0] + suffix + ".MPC"
        with open(out, "wb") as f:
            f.write(bytes(mpc))
        log("[DONE] saved: %s (%d bytes, original untouched)" % (out, len(mpc)))
    if both and (touch_fls or touch_mpc):
        out = os.path.splitext(paths["fls"])[0] + suffix + ".bin"
        with open(out, "wb") as f:
            f.write(bytes(fls) + bytes(mpc))
        log("[DONE] saved: %s (%d bytes combined, original untouched)" % (out, len(fls) + len(mpc)))
    if not (touch_fls or touch_mpc):
        log("[INFO] nothing changed on disk")

# ---------------- CLI ----------------

def run_diff(pa, pb):
    """Explain byte differences between two dumps (tagged by role: blob/key/mpc-blob)."""
    a = open(pa, "rb").read()
    b = open(pb, "rb").read()
    if len(a) != len(b):
        print("SIZES DIFFER: %d vs %d bytes - not comparable as-is" % (len(a), len(b)))
    n = min(len(a), len(b))
    diffs = [i for i in range(n) if a[i] != b[i]]
    if not diffs:
        print("IDENTICAL (%d bytes compared)" % n)
        return
    ranges = []
    for i in diffs:
        if ranges and i <= ranges[-1][1] + 8:
            ranges[-1][1] = i
        else:
            ranges.append([i, i])
    print("%d differing bytes in %d range(s):" % (len(diffs), len(ranges)))
    def tag(s):
        if 0x80300 <= s < 0x80386: return " [key]"
        if 0x7FF00 <= s < 0x7FF80: return " [blob R1]"
        if 0x9FF00 <= s < 0x9FF80: return " [blob R2]"
        if 0x1BFF00 <= s < 0x1BFF80: return " [blob R3]"
        if 0x1FFF00 <= s < 0x200000: return " [blob R4]"
        if 0x27FF00 <= s < 0x280000: return " [blob R0/mpc]"
        if 0x200000 <= s < 0x280000: return " [mpc]"
        return ""
    for s0, e0 in ranges[:60]:
        print("  0x%06X..0x%06X (%6d B)%s" % (s0, e0, e0 - s0 + 1, tag(s0)))
    if len(ranges) > 60:
        print("  ... and %d more ranges" % (len(ranges) - 60))

def predict_outputs(paths, fixlist):
    """Output files a fix run would write, so callers can warn before overwriting."""
    out = []
    do_blobs = any(f[0] == "blobs" for f in fixlist)
    suffix = "_signed" if do_blobs else "_fixed"
    touch_fls = do_blobs or any(f[0] == "flash-crc" for f in fixlist) or any(f[0] == "bootpage-complement" and f[1] == "fls" for f in fixlist)
    touch_mpc = do_blobs or any(f[0] == "bootpage-complement" and f[1] == "mpc" for f in fixlist)
    both = "fls" in paths and "mpc" in paths
    if touch_fls:
        out.append(os.path.splitext(paths["fls"])[0] + suffix + ".FLS")
    if touch_mpc:
        out.append(os.path.splitext(paths["mpc"])[0] + suffix + ".MPC")
    if both and (touch_fls or touch_mpc):
        out.append(os.path.splitext(paths["fls"])[0] + suffix + ".bin")
    return out

def run_cli(args):
    if args and args[0] == "--diff":
        if len(args) < 3:
            print("usage: med9_checker.py --diff <fileA> <fileB>")
            return
        run_diff(args[1], args[2])
        return
    overwrite = "--overwrite" in args
    paths = [a for a in args if not a.startswith("--")]
    files = {}
    for p in paths:
        kind = parse_layout(os.path.getsize(p))
        if kind == "combined":
            files["fls"] = p; files["mpc"] = p   # same path = combined handling
        elif kind == "fls": files["fls"] = p
        elif kind == "mpc": files["mpc"] = p
        elif kind == "epr": files["epr"] = p
        else: print("[FAIL] unknown layout:", p)
    log = lambda s: print(s)
    res = run_checks(log, files)
    if not res: return
    data, fixlist = res
    if fixlist:
        existing = [o for o in predict_outputs(files, fixlist) if os.path.exists(o)]
        if existing and not overwrite:
            log("[WARN] output file(s) already exist - refusing to overwrite:")
            for o in existing:
                log("       " + o)
            log("       delete them or rerun with --overwrite")
            return
        apply_fixes_multi(log, files, data, fixlist)

# ---------------- EEPROM tools window (E2PA style) ----------------

def open_eeprom(initial_path=None, root=None):
    """EEPROM tools: 2/4 KB block checksums, immo-off, VIN and PRGID edits."""
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    win = tk.Toplevel(root) if root is not None else tk.Tk()
    win.title(f"MED9 EEPROM analyser {APP_VERSION}")
    win.geometry("820x620+80+80")
    win.minsize(760, 590)
    win.configure(bg="#f0f0f0")

    state = {"data": None, "path": None, "slots": [], "immo_applied": False}
    panel_vars = {}

    top = ttk.Frame(win, padding=4)
    top.pack(fill="x")
    body = ttk.Frame(win)
    body.pack(fill="both", expand=True)
    logframe = ttk.Frame(body)
    logframe.pack(side="left", fill="both", expand=True, padx=(6, 0), pady=4)
    logw = tk.Text(logframe, bg="#ffffff", fg="#000000", font=("Consolas", 9),
                   width=48,
                   state="disabled", wrap="none")
    logscroll = ttk.Scrollbar(logframe, command=logw.yview)
    logscroll.pack(side="right", fill="y")
    logw.config(yscrollcommand=logscroll.set)
    logw.pack(side="left", fill="both", expand=True)
    def log(s):
        logw.config(state="normal")
        logw.insert("end", s + "\n")
        logw.see("end")
        logw.config(state="disabled")
        win.update_idletasks()

    def load(path):
        if not path or not os.path.isfile(path):
            return
        try:
            with open(path, "rb") as source:
                data = source.read()
        except OSError as exc:
            log("[FAIL] Could not load EEPROM: %s" % exc)
            return
        if len(data) not in SIZES_EPR:
            log("[FAIL] %s: %d bytes (expected 2048 or 4096)"
                % (os.path.basename(path), len(data)))
            return
        state["data"] = bytearray(data)
        state["path"] = path
        state["immo_applied"] = False
        immo_button.config(state="normal")
        pathvar.set(path)
        log("-" * 46)
        log("Loaded EEPROM (%d bytes)" % len(data))
        log("%s" % os.path.basename(path))
        refresh()

    def refresh():
        data = state["data"]
        if data is None:
            return
        checksums = eeprom.verify_checksums(data)
        mismatches = [row for row in checksums if not row["valid"]]
        log("Block checksums: %d/%d valid"
            % (len(checksums) - len(mismatches), len(checksums)))
        for row in mismatches:
            log("[WARN] %s @0x%03X: %04X (expected %04X)"
                % (row["block"], row["checksum_offset"], row["stored"], row["expected"]))
        if not mismatches:
            log("All checksums ok.")
        immo_status.config(text="Offset 0x59: %02X%s" % (
            data[0x59], " (applied)" if state["immo_applied"] else ""))
        recs, bad, extra = epr_verify(bytes(data))
        log("records: %d (crc-valid chain)" % len(recs))
        seen = set()
        for off, size, idb, lenb in recs:
            if idb in (0x02, 0x04, 0x05, 0x0A) and idb not in seen:
                seen.add(idb)
                log("  id 0x%02X @%04X: %s" % (idb, off, cstr(data, off+2, min(20, size-4))))
        if bad:
            log("[WARN] %d stale record(s): %s" % (len(bad), [(hex(a), s) for a, s in bad]))
        if extra:
            log("non-record areas: %s (not decoded, untouched)"
                % ", ".join("0x%03X(%d B)" % (a, s) for a, s in extra))
        state["slots"] = epr_find_vins(data)
        immo_ids = epr_find_immo_ids(data)
        for key, label, copies in (("vin", "VIN", state["slots"]),
                                    ("immo_id", "Immo ID", immo_ids)):
            values = {slot[1] for slot in copies}
            entry = panel_vars[key]
            entry.delete(0, "end")
            if len(values) == 1:
                value = next(iter(values))
                entry.insert(0, value)
                log("%s: %s (%d stored copies)" % (label, value, len(copies)))
            elif values:
                log("[WARN] %s copies disagree; enter the correct value before Apply" % label)
            else:
                log("%s: not found in checksum-valid identity records" % label)
        decode_prgid()

    def do_verify():
        if state["data"] is None:
            messagebox.showinfo("EEPROM", "Load an EEPROM first"); return
        log("Verifying checksums...")
        refresh()

    def do_fix():
        if state["data"] is None:
            messagebox.showinfo("EEPROM", "Load an EEPROM first"); return
        mismatches = [row for row in eeprom.verify_checksums(state["data"])
                      if not row["valid"]]
        if mismatches:
            state["data"][:] = eeprom.repair_checksums(state["data"])
            for row in mismatches:
                log("[FIX] %s checksum @0x%03X: %04X -> %04X"
                    % (row["block"], row["checksum_offset"], row["stored"], row["expected"]))
            refresh()
            log("[OK] repaired %d checksum(s) - use Save as... to write the file"
                % len(mismatches))
        else:
            log("Nothing to fix - all block checksums valid.")

    def do_immo_off():
        if state["data"] is None:
            messagebox.showinfo("EEPROM", "Load an EEPROM first", parent=win)
            return
        if state["immo_applied"]:
            log("IMMO OFF already applied to this loaded image.")
            return
        before = state["data"][0x59]
        state["data"][:] = eeprom.immo_off(state["data"])
        state["immo_applied"] = True
        immo_button.config(state="disabled")
        log("[IMMO] offset 0x59: %02X -> %02X" % (before, state["data"][0x59]))
        copies = "0x060, 0x840, 0x860" if len(state["data"]) == 4096 else "0x060"
        log("[IMMO] copied block 0x040-0x05F to %s" % copies)
        log("[IMMO] block checksums repaired automatically")
        refresh()
        log("[OK] IMMO OFF applied - use Save as... to write the file")

    def do_apply():
        if state["data"] is None:
            messagebox.showinfo("EEPROM", "Load an EEPROM first"); return
        vin = panel_vars["vin"].get().strip().upper()
        immo_id = panel_vars["immo_id"].get().strip().upper()
        before = bytes(state["data"])
        try:
            vin_count, id_count = epr_set_identity(state["data"], vin, immo_id)
        except ValueError as exc:
            log("[FAIL] %s" % exc)
            return
        if state["data"] == before:
            log("No VIN or Immo ID changes entered.")
            return
        log("[APPLY] updated %d VIN copies and %d Immo ID copies; checksums repaired"
            % (vin_count, id_count))
        refresh()
        log("[OK] applied - use Save as... to write the file")

    def do_save():
        if state["data"] is None:
            return
        base = os.path.splitext(state["path"])[0] + "_edited.EPR" if state["path"] else "eeprom_edited.EPR"
        p = filedialog.asksaveasfilename(parent=win, initialfile=os.path.basename(base),
                                         defaultextension=".EPR",
                                         filetypes=[("EEPROM", "*.eep *.EEP *.epr *.EPR *.e2p *.E2P *.bin *.BIN"), ("All", "*.*")])
        if not p:
            return
        try:
            with open(p, "wb") as output:
                output.write(state["data"])
        except OSError as exc:
            log("[FAIL] Could not save EEPROM: %s" % exc)
            return
        log("[DONE] saved: %s" % p)

    def decode_prgid():
        """decode the PRGID record (id 0x0B, size 32) and populate the FLASH panel"""
        data = state["data"]
        if data is None:
            return
        state.pop("prgid_off", None)
        for off, size, idb, lenb in epr_scan(bytes(data)):
            if idb != 0x0B or size != 32:
                continue
            p = data[off+2:off+size-2]
            for key, val in (("wcount", "%d" % p[7]), ("wsucc", "%d" % p[8]),
                             ("fpc", p[0:6].hex().upper()), ("state", "%d" % p[6])):
                e = prgid_vars[key]
                st = e.cget("state")
                e.config(state="normal")
                e.delete(0, "end"); e.insert(0, val)
                e.config(state=st)
            # complement check
            n_ok = p[19] == (~p[7] & 0xFF) and p[20] == (~p[8] & 0xFF)
            prgid_vars["cpl"].config(text="compl ok" if n_ok else "compl BAD",
                                     foreground="#1a7a1a" if n_ok else "#aa0000")
            state["prgid_off"] = off
            return
        for key in ("wcount", "wsucc", "fpc", "state"):
            entry = prgid_vars[key]
            entry_state = entry.cget("state")
            entry.config(state="normal")
            entry.delete(0, "end")
            entry.config(state=entry_state)
        prgid_vars["cpl"].config(text="not found", foreground="#aa0000")

    def do_update_prgid():
        data = state["data"]
        if data is None or "prgid_off" not in state:
            messagebox.showinfo("EEPROM", "Load an EEPROM first"); return
        off = state["prgid_off"]
        idb = data[off]
        lenb = data[off+1]
        try:
            wc = int(prgid_vars["wcount"].get())
            ws = int(prgid_vars["wsucc"].get())
        except ValueError:
            messagebox.showerror("EEPROM", "Write Counter / Success must be numbers"); return
        if not (0 <= wc <= 255 and 0 <= ws <= 255):
            messagebox.showerror("EEPROM", "values must be 0-255"); return
        # write attempt + success + complements
        data[off+2+7] = wc
        data[off+2+8] = ws
        data[off+2+19] = ~wc & 0xFF
        data[off+2+20] = ~ws & 0xFF
        epr_restamp(data, off, 32, idb, lenb)
        log("[PRGID] write counter=%d, success=%d + complements updated, crc re-stamped" % (wc, ws))
        decode_prgid()

    # ---- layout: white log left, control panel right (E2PA style) ----
    pathvar = tk.StringVar()
    ttk.Button(top, text="Load EPR...", command=lambda: load(
        browse_dump(filedialog.askopenfilename, parent=win, title="Load EEPROM",
            filetypes=[("EEPROM", "*.eep *.EEP *.epr *.EPR *.e2p *.E2P *.bin *.BIN"), ("All", "*.*")]))).pack(side="left")
    ttk.Label(top, textvariable=pathvar, width=52).pack(side="left", padx=6)

    panel = ttk.LabelFrame(body, text=" EEPROM ", padding=6)
    panel.pack(side="right", fill="y", padx=(4, 6), pady=4)

    for r, key, label in ((0, "vin", "VIN"), (1, "immo_id", "Immo ID")):
        ttk.Label(panel, text=label).grid(row=r, column=0, sticky="w", padx=4)
        e = ttk.Entry(panel, font=("Consolas", 9), width=20)
        e.grid(row=r, column=1, sticky="we", padx=4, pady=1)
        panel_vars[key] = e
    ttk.Button(panel, text="Apply", command=do_apply)\
        .grid(row=2, column=0, columnspan=2, sticky="we", padx=4, pady=(6, 2))
    ttk.Separator(panel).grid(row=3, column=0, columnspan=2, sticky="we", padx=2, pady=4)

    # ---- FLASH PRGID panel ----
    ttk.Label(panel, text="FLASH (PRGID)", font=("Consolas", 9, "bold"))\
        .grid(row=4, column=0, columnspan=2, sticky="w", padx=4)
    prgid_vars = {}
    for r, key, label, ro in ((5, "wcount", "Write Counter", False),
                              (6, "wsucc", "Write Success", False),
                              (7, "fpc", "Prog Code", True),
                              (8, "state", "State", True)):
        ttk.Label(panel, text=label).grid(row=r, column=0, sticky="w", padx=4)
        e = ttk.Entry(panel, font=("Consolas", 9), width=14)
        if ro:
            e.config(state="readonly")
        e.grid(row=r, column=1, sticky="we", padx=4, pady=1)
        prgid_vars[key] = e
    prgid_vars["cpl"] = ttk.Label(panel, text="", font=("Consolas", 8))
    prgid_vars["cpl"].grid(row=9, column=0, columnspan=2, sticky="w", padx=4)
    ttk.Button(panel, text="Update", command=do_update_prgid)\
        .grid(row=10, column=0, columnspan=2, sticky="we", padx=4, pady=(4, 2))
    ttk.Separator(panel).grid(row=11, column=0, columnspan=2, sticky="we", padx=2, pady=4)

    ttk.Button(panel, text="Verify checksums", command=do_verify)\
        .grid(row=12, column=0, columnspan=2, sticky="we", padx=4, pady=2)
    ttk.Button(panel, text="Fix CRCs", command=do_fix)\
        .grid(row=13, column=0, columnspan=2, sticky="we", padx=4, pady=2)
    ttk.Separator(panel).grid(row=14, column=0, columnspan=2, sticky="we", padx=2, pady=4)
    immo_button = ttk.Button(panel, text="IMMO OFF", command=do_immo_off, state="disabled")
    immo_button.grid(row=15, column=0, columnspan=2, sticky="we", padx=4, pady=2)
    immo_status = ttk.Label(panel, text="Load EEPROM first", font=("Consolas", 8))
    immo_status.grid(row=16, column=0, columnspan=2, sticky="w", padx=4)
    ttk.Label(panel, text="Apply once to an immo-on image.", font=("Consolas", 8))\
        .grid(row=17, column=0, columnspan=2, sticky="w", padx=4, pady=(0, 4))
    ttk.Button(panel, text="Save as...", command=do_save)\
        .grid(row=18, column=0, columnspan=2, sticky="we", padx=4, pady=2)

    if initial_path:
        load(initial_path)
    else:
        log("MED9 EEPROM analyser - load a 2048 or 4096 byte EEPROM")
    return win

# ---------------- GUI ----------------

def run_gui():
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    # DPI awareness BEFORE any window exists: without it Windows bitmap-stretches
    # the whole UI on scaled displays and the fonts look blurry
    dpi_scale = 1.0
    if os.name == "nt":
        import ctypes as _ct
        try:
            _ct.windll.shcore.SetProcessDpiAwareness(1)   # system DPI aware
        except Exception:
            try:
                _ct.windll.user32.SetProcessDPIAware()
            except Exception:
                pass

    try:
        from tkinterdnd2 import DND_FILES, TkinterDnD
        root = TkinterDnD.Tk()
        dnd = True
    except Exception:
        root = tk.Tk()
        dnd = False

    root.title(f"MED9 dump checker {APP_VERSION} - CRC / signing")
    try:
        dpi = root.winfo_fpixels("1i")
        if dpi > 0:
            dpi_scale = dpi / 96.0
            # align Tk's point->pixel conversion with the real screen DPI so
            # point-sized fonts render sharp instead of scaled
            root.tk.call("tk", "scaling", dpi / 72.0)
    except Exception:
        pass
    root.geometry("%dx%d" % (round(880 * dpi_scale), round(532 * dpi_scale)))

    files = {"fls": None, "mpc": None, "epr": None}
    flash_mode = tk.StringVar(value="Flash mode: load a flash file")
    ZONE_EMPTY_BG = "#e9ede9"         # basic grey with a slight green tint
    ZONE_FULL_BG = "#dfe9df"          # same tint, a touch stronger when loaded
    ZONE_FG = "#000000"               # black text

    def human_size(n):
        if n >= 1024 * 1024:
            return "%.2f MB (%d bytes)" % (n / 1048576.0, n)
        return "%.1f KB (%d bytes)" % (n / 1024.0, n)

    def short_size(n):
        return "%.2f MB" % (n / 1048576.0) if n >= 1048576 else "%.1f KB" % (n / 1024.0)

    def wrap_name(name, width=30):
        """long file names wrap onto two rows (no truncation)"""
        if len(name) <= width:
            return name
        mid = (len(name) + 1) // 2
        cut = 0
        for sep in ("/", "\\", "_", "-", " "):
            cut = max(cut, name.rfind(sep, 0, mid + 6))
        if cut < 6:
            cut = mid
        return name[:cut] + "\n" + name[cut:]

    # log frame is created up front so the log Text can be its real child
    # (an in_= repack into a later sibling leaves the Text stacked underneath
    #  that frame's background -> invisible log)
    logframe = ttk.Frame(root, padding=(6, 0, 6, 4))
    logbox = tk.Text(logframe, wrap="none", bg="#101010", fg="#00e000",
                     insertbackground="#00e000", font=("Consolas", 9), height=10)
    scr = ttk.Scrollbar(logframe, command=logbox.yview)
    logbox.config(yscrollcommand=scr.set)
    scr.pack(side="right", fill="y")
    logbox.pack(side="left", fill="both", expand=True)
    def log(s):
        logbox.insert("end", s + "\n"); logbox.see("end"); root.update_idletasks()

    def assign(chip, path):
        """assign a file to a zone; combined dumps fill both flash+mpc."""
        if not path or not os.path.isfile(path):
            return
        kind = parse_layout(os.path.getsize(path))
        if kind == "combined":
            files["fls"] = path; files["mpc"] = path
            for chip2, tag in (("fls", "flash"), ("mpc", "mpc")):
                lbl = zone_labels[chip2]
                lbl.config(text="%s\n[%s] %s" % (wrap_name(os.path.basename(path)),
                                                 tag, short_size(os.path.getsize(path))),
                           bg=ZONE_FULL_BG, fg=ZONE_FG)
            log("[LOAD] combined dump -> flash + mpc")
        elif kind in ("fls", "mpc", "epr"):
            files[kind] = path
            lbl = zone_labels[kind]
            lbl.config(text="%s\n[%s] %s" % (wrap_name(os.path.basename(path)),
                                             kind, short_size(os.path.getsize(path))),
                       bg=ZONE_FULL_BG, fg=ZONE_FG)
            log("[LOAD] %s: %s (%s)" % (kind, os.path.basename(path), human_size(os.path.getsize(path))))
        else:
            log("[FAIL] %s: unknown layout (%d bytes)" % (os.path.basename(path), os.path.getsize(path)))
        if kind in ("combined", "fls"):
            with open(path, "rb") as source:
                profile = flash.detect_profile(source.read(SIZE_FLS))
            flash_mode.set("Flash mode: " + profile.label)
            log("[MODE] " + profile.label)

    def clear_zone(chip):
        files[chip] = None
        if chip == "fls":
            flash_mode.set("Flash mode: load a flash file")
        zone_labels[chip].config(text="drop file here\nclick to browse", bg=ZONE_EMPTY_BG, fg=ZONE_FG)
        log("[CLEAR] %s zone emptied" % chip.upper())

    def browse(chip):
        p = browse_dump(filedialog.askopenfilename, parent=root, title="Load %s" % chip.upper(),
            filetypes=[("MED9 dumps", "*.bin *.BIN *.fls *.FLS *.ori *.ORI *.mod *.MOD *.mpc *.MPC *.eep *.EEP *.epr *.EPR *.e2p *.E2P"), ("All", "*.*")])
        assign(chip, p)

    def drop(chip):
        def handler(e):
            p = e.data.strip("{}").split("} {")[0].strip("{}")
            assign(chip, p)
        return handler

    zone_labels = {}
    zones = ttk.Frame(root, padding=8); zones.pack(fill="x")
    def zone(chip, title):
        f = ttk.LabelFrame(zones, text=title, padding=6)
        f.pack(side="left", fill="both", expand=True, padx=5)
        f.configure(height=130)
        lbl = tk.Label(f, text="drop file here\nclick to browse",
                       bg=ZONE_EMPTY_BG, fg=ZONE_FG,
                       font=("Consolas", 10, "bold"), width=30, height=4,
                       relief="groove", bd=2, cursor="hand2")
        lbl.pack(fill="both", expand=True)
        lbl.bind("<Button-1>", lambda e, c=chip: browse(c))
        zone_labels[chip] = lbl
        row = ttk.Frame(f); row.pack(fill="x", pady=(6, 0))
        ttk.Button(row, text="Browse...", command=lambda: browse(chip)).pack(side="left", padx=(0, 4))
        ttk.Button(row, text="Clear", command=lambda: clear_zone(chip)).pack(side="left")
        if dnd:
            lbl.drop_target_register(DND_FILES)
            lbl.dnd_bind("<<Drop>>", drop(chip))
        return f
    zone("fls", "FLASH (FLS, 2 MB)")
    zone("mpc", "MPC (internal, 512 KB)")
    zone("epr", "EEPROM (2 / 4 KB, optional)")
    ttk.Label(root, textvariable=flash_mode, padding=(12, 2))\
        .pack(fill="x")

    btns = ttk.Frame(root, padding=4); btns.pack(fill="x")

    def do_check(fix=False):
        paths = {k: v for k, v in files.items() if v}
        if not paths:
            messagebox.showerror("MED9 checker", "Load a flash and/or MPC file first")
            return
        res = run_checks(log, paths)
        if not res: return
        data, fixlist = res
        if fix and fixlist:
            if any(f[0] == "blobs" for f in fixlist) and not files.get("mpc"):
                log("[FAIL] re-signing also needs the MPC loaded (region 0's blob lives there)")
                return
            msg = ("Fix %d issue(s)?\n(corrected copies are saved, originals untouched)"
                   % len(fixlist))
            existing = [o for o in predict_outputs(paths, fixlist) if os.path.exists(o)]
            if existing:
                msg += "\n\nWARNING: this will OVERWRITE existing file(s):\n" + \
                       "\n".join(os.path.basename(o) for o in existing)
            if messagebox.askyesno("Correct", msg):
                apply_fixes_multi(log, paths, data, fixlist)
            else:
                log("[INFO] cancelled - nothing written")
        elif fix and not fixlist:
            log("[INFO] nothing to correct - see check results above")
        return data, fixlist

    def clear_all():
        for chip in ("fls", "mpc", "epr"):
            if files.get(chip):
                clear_zone(chip)
        log("[CLEAR] all zones emptied")

    def open_folder():
        any_path = next((v for v in files.values() if v), None)
        if not any_path:
            messagebox.showinfo("Open folder", "Load a file first")
            return
        os.startfile(os.path.dirname(os.path.abspath(any_path)))

    ttk.Button(btns, text="Run checks", command=lambda: do_check(False)).pack(side="left", padx=4)
    ttk.Button(btns, text="Check & correct", command=lambda: do_check(True)).pack(side="left", padx=4)
    ttk.Button(btns, text="EEPROM tools", command=lambda: open_eeprom(files.get("epr"), root)).pack(side="left", padx=4)
    ttk.Button(btns, text="Open folder", command=open_folder).pack(side="left", padx=4)
    ttk.Button(btns, text="Clear all files", command=clear_all).pack(side="left", padx=4)
    ttk.Button(btns, text="Clear log", command=lambda: logbox.delete("1.0", "end")).pack(side="left", padx=4)

    # manage the log frame only now, so its cavity order comes after zones/buttons
    logframe.pack(fill="both", expand=True)
    st = ttk.Label(root, text="drag & drop enabled" if dnd else "drag&drop needs: pip install tkinterdnd2 (optional)")
    st.pack(fill="x")
    log("[READY] Load FLASH. MPC is required for signing profiles only.")
    log("        A combined 2.5MB dump fills FLASH + MPC. EEPROM is optional.")

    root.mainloop()
    return root

if __name__ == "__main__":
    if len(sys.argv) > 1:
        run_cli(sys.argv[1:])
    else:
        run_gui()
