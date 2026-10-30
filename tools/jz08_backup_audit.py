#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""JZ08 local full-eMMC backup audit. READ ONLY. No ADB, USB, EDL or device writes.
Reports contain only integrity flags, generic GPT partition labels and hashes.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import zipfile
import zlib

EXPECTED_BYTES = 3909091328
EXPECTED_SHA256 = "2271764802356a14b8d51ba0950abc9e1af3634e260d488cdd9128c3e4fb34bc"
SECTOR = 512
EXPECTED_PARTITIONS = {14: "modemst2", 22: "boot", 23: "system", 26: "recovery", 27: "userdata"}
HEADER = struct.Struct("<8sIIIIQQQQ16sQIII")
MAX_ENTRY_BYTES = 4 * 1024 * 1024


class AuditError(ValueError):
    pass


def read_at(fp, offset: int, count: int) -> bytes:
    fp.seek(offset)
    out = fp.read(count)
    if len(out) != count:
        raise AuditError("truncated image while reading GPT")
    return out


def read_gpt(fp, lba: int, total_sectors: int):
    h = read_at(fp, lba * SECTOR, SECTOR)
    if len(h) < HEADER.size:
        raise AuditError("GPT header too short")
    (sig, revision, hsize, saved_crc, reserved, here, other,
     first_usable, last_usable, _guid, table_lba, n, width, table_crc) = HEADER.unpack_from(h)
    if sig != b"EFI PART" or revision != 0x00010000:
        raise AuditError("GPT signature/revision mismatch")
    if not 92 <= hsize <= SECTOR or reserved != 0:
        raise AuditError("invalid GPT header size/reserved")
    hh = bytearray(h[:hsize])
    hh[16:20] = b"\x00" * 4
    if (zlib.crc32(hh) & 0xffffffff) != saved_crc:
        raise AuditError("GPT header CRC32 mismatch")
    if here != lba or other != (total_sectors - 1 if lba == 1 else 1):
        raise AuditError("GPT primary/secondary LBA linkage mismatch")
    if not 2 <= first_usable <= last_usable < total_sectors - 1:
        raise AuditError("invalid usable LBA bounds")
    if not 1 <= n <= 1024 or width < 128 or width % 8:
        raise AuditError("invalid GPT partition table shape")
    table_bytes = n * width
    if table_bytes > MAX_ENTRY_BYTES:
        raise AuditError("GPT entry table exceeds safety limit")
    start = table_lba * SECTOR
    if start < 2 * SECTOR or start + table_bytes > total_sectors * SECTOR:
        raise AuditError("GPT entry table outside image")
    table = read_at(fp, start, table_bytes)
    if (zlib.crc32(table) & 0xffffffff) != table_crc:
        raise AuditError("GPT entries CRC32 mismatch")
    parts = {}
    intervals = []
    for i in range(n):
        b = table[i * width:(i + 1) * width]
        if b[:16] == b"\x00" * 16:
            continue
        a, z = struct.unpack_from("<QQ", b, 32)
        if a < first_usable or z > last_usable or a > z:
            raise AuditError("GPT partition outside usable range")
        label = b[56: min(128, width)].decode("utf-16-le", errors="replace").rstrip("\x00")
        parts[i + 1] = label
        intervals.append((a, z))
    intervals.sort()
    if any(intervals[k][0] <= intervals[k - 1][1] for k in range(1, len(intervals))):
        raise AuditError("overlapping GPT partitions")
    return {"parts": parts, "count": len(parts), "table_crc": table_crc,
            "bounds": [first_usable, last_usable]}


def audit_image(path: Path, *, expected_size=EXPECTED_BYTES, expected_sha=EXPECTED_SHA256,
                progress=None) -> dict:
    if not path.is_file() or path.is_symlink():
        raise AuditError("regular backup file required (symlinks forbidden)")
    stat = path.stat()
    if stat.st_size != expected_size or stat.st_size % SECTOR:
        raise AuditError("eMMC image size mismatch")
    total = stat.st_size // SECTOR
    with path.open("rb") as fp:
        mbr = read_at(fp, 0, SECTOR)
        if mbr[510:512] != b"\x55\xaa" or mbr[450] != 0xEE:
            raise AuditError("missing protective MBR")
        primary = read_gpt(fp, 1, total)
        secondary = read_gpt(fp, total - 1, total)
        if primary != secondary:
            raise AuditError("primary/backup GPT do not match")
        if primary["count"] != 27:
            raise AuditError("OEM GPT is not 27 populated partitions")
        for num, label in EXPECTED_PARTITIONS.items():
            if primary["parts"].get(num, "").lower() != label:
                raise AuditError(f"OEM partition p{num} is not {label}")
        digest = hashlib.sha256()
        fp.seek(0)
        completed = 0
        next_percent = 0
        while True:
            chunk = fp.read(8 * 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            completed += len(chunk)
            pct = completed * 100 // stat.st_size
            if progress and pct >= next_percent:
                progress(pct)
                next_percent = pct + 5
        actual = digest.hexdigest()
        if actual.lower() != expected_sha.lower():
            raise AuditError("backup SHA256 does not match verified baseline")
    return {"status": "LOCAL_BACKUP_VERIFIED", "flash_allowed": False,
            "bytes": stat.st_size, "sectors": total, "sha256": actual,
            "gpt_crc32": "PASS_BOTH", "gpt_partitions": primary["count"],
            "protected_partition_14": primary["parts"][14],
            "expected_partition_labels": EXPECTED_PARTITIONS,
            "hardware_boot_tested": False}


def main():
    p = argparse.ArgumentParser(description="JZ08: verify local image and GPT; NEVER flash")
    p.add_argument("--backup", type=Path, required=True, help="local full eMMC .bin")
    p.add_argument("--output", type=Path, default=Path("/storage/emulated/0/Download"))
    a = p.parse_args()
    print("\033[32m[JZ08] READ-ONLY BACKUP AUDIT\033[0m | EDL/FLASH DISABLED", flush=True)
    result = {"board": "JZ08-3000-NKV 1.0",
              "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
              "flash_allowed": False, "status": "REJECTED"}
    try:
        result.update(audit_image(a.backup, progress=lambda n: print(f"\rSHA256 {n:3d}%", end="", flush=True)))
        print("\nPASS: OEM GPT primary+backup / p14 NV / full SHA256")
    except (OSError, AuditError) as e:
        result["error"] = str(e)
        print("\nFAIL:", str(e), file=sys.stderr)
    report = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    out = a.output / "XARKON_JZ08_REPORTS"
    out.mkdir(parents=True, exist_ok=True)
    dest = out / ("XARKON_JZ08_BACKUP_AUDIT_" +
                  dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d_%H%M%S") + ".zip")
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("РЕЗУЛЬТАТ.json", report)
        z.writestr("ОТЧЁТ.txt", "Локальный отчёт JZ08; прошивка заблокирована.\n" +
                   "Статус: " + result["status"] + "\n" +
                   ("Ошибка: " + result["error"] + "\n" if "error" in result else "GPT и SHA256: OK\n"))
    print("REPORT:", dest)
    return 0 if result["status"] == "LOCAL_BACKUP_VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
