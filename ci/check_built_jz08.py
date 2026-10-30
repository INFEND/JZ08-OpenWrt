#!/usr/bin/env python3
"""Reject misleading green CI builds with missing modem/router functionality.
Diagnostic verification only; does not produce flashable images.
"""
import argparse
import json
import pathlib
import re
import sys

MUST_HAVE = {
    "kernel", "base-files", "procd", "busybox", "luci", "luci-base",
    "luci-i18n-base-ru", "modemmanager", "rmtfs", "kmod-qcom-rproc-modem",
    "kmod-qcom-rproc-wcnss", "kmod-wcn36xx", "kmod-usb-gadget-ncm",
    "uhttpd", "configs-mifi"
}

def check(source, log, root):
    errors = []
    text = log.read_text(errors="replace")
    critical = [x.strip() for x in text.splitlines() if "error: recursive dependency detected" in x.lower()]
    if critical:
        errors.append(f"{len(critical)} Kconfig recursive dependency errors")
    manifests = list((root / "bin/targets").rglob("*jz08*.manifest"))
    if len(manifests) != 1:
        errors.append(f"expected exactly 1 JZ08 package manifest, found {len(manifests)}")
    packages = set()
    if manifests:
        for row in manifests[0].read_text(errors="replace").splitlines():
            if " - " in row: packages.add(row.split(" - ", 1)[0])
        absent = MUST_HAVE.difference(packages)
        if absent:
            errors.append("missing required packages: " + ", ".join(sorted(absent)))
    kconfig = (root / ".config").read_text(errors="replace")
    if "CONFIG_TARGET_msm89xx_msm8916_DEVICE_generic-jz08-3000-nkv=y" not in kconfig:
        errors.append("selected target is not generic-jz08-3000-nkv")
    # Separate copied DTS tree and final DTB: ensure that the kernel actually built our DTB.
    dtbs = list((root / "build_dir").rglob("msm8916-generic-jz08-3000-nkv.dtb"))
    if not dtbs:
        errors.append("JZ08 DTB was not compiled")
    else:
        if not any(p.stat().st_size > 1000 for p in dtbs):
            errors.append("JZ08 DTB is unexpectedly small")
    report = {
        "board": "JZ08-3000-NKV 1.0",
        "status": "BUILD_CHECKS_PASS_ONLY" if not errors else "REJECTED_DEVELOPMENT_BUILD",
        "hardware_tested": False,
        "flash_allowed": False,
        "required_packages": sorted(MUST_HAVE),
        "found_packages": sorted(packages),
        "dtb": [{"path":p.relative_to(root).as_posix(), "size":p.stat().st_size} for p in dtbs[:10]],
        "errors": errors,
    }
    out = source / "output/JZ08_BUILD_AUDIT.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({k:v for k,v in report.items() if k!="found_packages"}, indent=2, ensure_ascii=False))
    if errors:
        raise SystemExit(1)

if __name__ == "__main__":
    a=argparse.ArgumentParser()
    a.add_argument("--source", type=pathlib.Path, required=True)
    a.add_argument("--build-log", type=pathlib.Path, required=True)
    a.add_argument("--openwrt", type=pathlib.Path, required=True)
    args=a.parse_args()
    check(args.source.resolve(), args.build_log.resolve(), args.openwrt.resolve())
