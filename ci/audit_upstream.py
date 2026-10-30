#!/usr/bin/env python3
"""Verify upstream pins and source invariants without running any upstream code."""
from __future__ import annotations
import hashlib
import json
import pathlib
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
sha_up = "c2e2dd5afc6ec4e8be55cfc952a1fce042e681c4"
sources = {
    "msm8916.mk": "https://raw.githubusercontent.com/rabbits0209/msm8916-xiaoxun-openwrt/" + sha_up + "/msm89xx/image/msm8916.mk",
    "diffconfig_mf68e": "https://raw.githubusercontent.com/rabbits0209/msm8916-xiaoxun-openwrt/" + sha_up + "/diffconfig_mf68e",
    "lcd_patch": "https://raw.githubusercontent.com/rabbits0209/msm8916-xiaoxun-openwrt/" + sha_up + "/msm89xx/patches-6.12/901-fbtft-fb_gc9107.patch",
}
def get(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "JZ08-source-audit"}),timeout=25) as r:
        data = r.read(1000000)
    if not data:
        raise RuntimeError("empty response")
    return data
data = {name:get(url) for name,url in sources.items()}
mk = data["msm8916.mk"].decode()
if "define Device/generic-mf68e" not in mk or "root=/dev/mmcblk0p14" not in mk:
    raise SystemExit("upstream reference profile changed unexpectedly")
if "ARTIFACTS := squashfs-gpt_both0.bin flash.sh firmware.zip" not in mk:
    raise SystemExit("upstream flash artifact list changed; review needed")
if "CONFIG_TARGET_msm89xx_msm8916_DEVICE_generic-mf68e=y" not in data["diffconfig_mf68e"].decode():
    raise SystemExit("missing MF68E reference config")
manifest = {
    "status": "REFERENCE_SOURCES_ONLY_NOT_FLASHABLE",
    "upstream": sha_up,
    "sha256": {n:hashlib.sha256(b).hexdigest() for n,b in data.items()}
}
(ROOT / "upstream-audit.json").write_text(json.dumps(manifest,indent=2)+"\n")
print("PASS: pinned source facts. Upstream flash.sh is incompatible with JZ08.")
