# JZ08: offline RAM-only test readiness gates

## Update 2026-11-01: separate complete RAM trial

The old embedded-initramfs candidate discussed below remains blocked. The new
`jz08-full-trial.yml` pipeline uses the normal 14,682,120-byte ARM64 kernel and
a separate complete OpenWrt initrd, avoiding the old kernel/DTB/initrd overlap.
The supplied LK2ND's real address override is documented by disassembly in
`board/evidence/`. The phone must obtain a positive, bounded OEM memory map
before packing or sending an image. This is a software gate, not proof of
successful execution on JZ08. USB uses the producer's matched legacy gadget
modules because that producer has CONFIG_USB_CONFIGFS disabled.

The full RAM trial has an independent 600-second recovery timer and tests a
fresh nonce, OpenWrt startup, HTTP LuCI, eMMC geometry and p26 restoration
separately. Persistent installation remains blocked. See
[the full trial instructions](FULL_TRIAL_RU.md). The historical gates below
describe the previous inspection-only candidate.

Status: **NOT FLASHABLE**, **NOT READY FOR HARDWARE RAM-ONLY TEST**.

The 1 November 2026 build [#41289116237](https://github.com/INFEND/JZ08-OpenWrt/actions/runs/41289116237)
published the complete offline engineering bundle (artifact ID `13079710359`).
The independent downstream audit [#41296104361](https://github.com/INFEND/JZ08-OpenWrt/actions/runs/41296104361)
**passed** after downloading the published artifact and rechecking kernel-appended
JZ08 DTB, embedded initramfs CPIO, extracted rootfs, Russian LuCI resources,
manifest and SHA256SUMS. Inner engineering ZIP SHA-256:
`e2a40cd0837fefd5ff0f78218780537bf7754ef6004d12ce4a7d7d26a306191a`.
This confirms **offline package completeness only**. It does not prove execution
on JZ08 or authorize `fastboot boot` with unverified load addresses.

## Offline gates that can be checked without the router

1. Preserve pinned source SHAs, the JZ08 DTB identity and build hashes.
2. Decode and fully extract the built rootfs; reject decompression errors.
3. Inspect extracted `/sbin/init` and `/bin/busybox`: executable ELF64
   AArch64, bounded PT_LOAD segments, and any PT_INTERP loader present inside
   the same rootfs. Record hashes in text/JSON only. **Never execute** extracted
   binaries on the CI host or upload the rootfs.
4. Keep the ordinary `boot.img` flagged as not RAM-only:
   `ramdisk_size=0` and `root=PARTLABEL=jz08-unconfigured-rootfs`.
   The separate `RAM_ONLY_INITRAMFS_CANDIDATE.img` embeds an audited initramfs,
   but its load addresses and device execution are not verified.
5. Publish images **only** inside the clearly marked NOT FLASHABLE engineering
   CI artifact for offline inspection, never as a flashable Release. Require
   the independent post-publication ZIP verifier to pass.

## Independent hardware-dependent gates still blocking any boot trial

- Obtain a verified JZ08 RAM map, bootloader load addresses and DTB memory
  ranges. A zero-sized DT memory node is not proof of valid RAM layout.
- The separate embedded initramfs has been validated **offline**. Before any
  hardware trial, establish an observable, non-persistent `/init` success marker
  (UART/USB only after its transport is proven). No dependence on writing an
  eMMC `/cache` marker.
- Validate that the exact bootloader path accepts a RAM-only load without
  writing GPT, boot, recovery, modemst or any OEM partition.
- Define a reliable power-cycle recovery and an independently observable
  success/failure criterion before a user is asked to test anything.
- Never substitute MF68E GPT, `flash.sh`, p14 rootfs, or a guessed LCD/GPIO.

**Decision:** passing the new offline userspace check strengthens the rootfs
audit only. It does not remove any hardware gate or authorize flashing.
