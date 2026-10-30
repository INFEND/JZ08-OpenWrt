#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Package the READ-ONLY backup auditor as a Python-runnable ZIP for Termux."""
from pathlib import Path
import hashlib
import json
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools/jz08_backup_audit.py"
DEST = ROOT / "dist/JZ08_SAFE_BACKUP_AUDIT.zip"
README = """XARKON JZ08 - ТОЛЬКО ЧТЕНИЕ / READ ONLY

Не является прошивкой. Не может записывать данные в MiFi.
Проверяет локальный заводской дамп eMMC и обе копии GPT.
Отчёт создаётся в /storage/emulated/0/Download/XARKON_JZ08_REPORTS.

Termux:
pkg install -y python
python /storage/emulated/0/Download/JZ08_SAFE_BACKUP_AUDIT.zip --backup /storage/emulated/0/Download/XARKON_MIFI_SAFE_COPY/flash_emmc_20261028_082457_verified.bin

Итог PASS подтверждает только совпадение дампа с известным SHA256
и корректную структуру GPT. Не подтверждает работоспособность OpenWrt.
"""
def pack():
    code = SOURCE.read_bytes()
    if not code.startswith(b"#!/usr/bin/env python3"):
        raise RuntimeError("unexpected entrypoint")
    DEST.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(DEST, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("__main__.py", code)
        z.writestr("README_RU.txt", README)
        z.writestr("SOURCE_SHA256.txt", hashlib.sha256(code).hexdigest() + "\n")
    with zipfile.ZipFile(DEST) as z:
        if z.testzip() is not None or "__main__.py" not in z.namelist():
            raise RuntimeError("ZIP self-test failed")
    digest = hashlib.sha256(DEST.read_bytes()).hexdigest()
    meta = {"name": DEST.name, "status": "READ_ONLY_NOT_FLASHABLE",
            "sha256": digest, "bytes": DEST.stat().st_size,
            "source_sha256": hashlib.sha256(code).hexdigest()}
    (DEST.parent / "JZ08_SAFE_BACKUP_AUDIT.sha256").write_text(
        f"{digest}  {DEST.name}\n", encoding="utf-8")
    (DEST.parent / "JZ08_SAFE_TOOL_MANIFEST.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(meta, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    pack()
