#!/usr/bin/env python3
"""Read-only source validation and conservative safeguards."""
import hashlib
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
REQUIRED = (
    "README.md", "board/jz08.json", "board/msm8916-generic-jz08-prototype.dts",
    "board/msm8916.mk.append", "board/diffconfig-jz08-build-only",
    "docs/PORTING.md", "docs/S24_INSTALL.md",
)

def check():
    errors = []
    for rel in REQUIRED:
        if not (ROOT / rel).is_file():
            errors.append("missing " + rel)
    if errors:
        return errors
    b = json.loads((ROOT / "board/jz08.json").read_text())
    o = b["oem"]
    if o["sectors"] * o["sector_size"] != o["emmc_bytes"]:
        errors.append("bad eMMC sector geometry")
    if o["gpt_partitions"] != 27 or o["partition_ids"]["14"] != "modemst2":
        errors.append("GPT mismatch: p14 must be modemst2")
    if b["firmware_flash_allowed"] is not False:
        errors.append("flashing must stay blocked")
    if b["proof"]["linux_init"] is not False or b["proof"]["openwrt_boot"] is not False:
        errors.append("unverified Linux/OpenWrt boot claim")
    if o["backup_sha256"] != "2271764802356a14b8d51ba0950abc9e1af3634e260d488cdd9128c3e4fb34bc":
        errors.append("backup SHA256 changed")
    dts = (ROOT / "board/msm8916-generic-jz08-prototype.dts").read_text()
    if 'status = "disabled"' not in dts:
        errors.append("LCD must remain disabled")
    target = (ROOT / "board/msm8916.mk.append").read_text()
    if "jz08-unconfigured-rootfs" not in target or "ARTIFACTS :=" not in target:
        errors.append("build-only failsafe missing")
    danger = re.compile(r"(?i)(?:^|/)(?:.*(?:imei|nvram|calibration|modemst1|modemst2|firehose|rawprogram|prog_emmc_firehose).*)$")
    banned = re.compile(r"(?im)^[^#\n]*\b(?:fastboot\s+flash|edl\s+w(?:\s|$)|qdl\s+--flash)\b")
    for p in ROOT.rglob("*"):
        if not p.is_file() or ".git" in p.parts:
            continue
        rel = p.relative_to(ROOT).as_posix()
        if danger.search(rel):
            errors.append("sensitive filename: " + rel)
        if p.suffix in (".py", ".sh", ".yml", ".yaml") and rel != "ci/validate.py":
            if banned.search(p.read_text(encoding="utf-8")):
                errors.append("dangerous command in " + rel)
    return errors

if __name__ == "__main__":
    errors = check()
    for error in errors:
        print("ERROR", error, file=sys.stderr)
    if errors:
        raise SystemExit(1)
    checksums = {rel: hashlib.sha256((ROOT / rel).read_bytes()).hexdigest() for rel in REQUIRED}
    (ROOT / "checksums-source.json").write_text(json.dumps(checksums, indent=2) + "\n")
    print("PASS: source verified, flashing BLOCKED")
