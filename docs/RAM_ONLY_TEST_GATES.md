# JZ08: offline RAM-only test readiness gates

Status: **NOT FLASHABLE**, **NOT READY FOR HARDWARE RAM-ONLY TEST**.

The 31 October build confirms kernel/DTB compilation, Android Sparse/SquashFS
integrity, and package manifest presence. It does not prove execution on JZ08.

## Offline gates that can be checked without the router

1. Preserve pinned source SHAs, the JZ08 DTB identity and build hashes.
2. Decode and fully extract the built rootfs; reject decompression errors.
3. Inspect extracted `/sbin/init` and `/bin/busybox`: executable ELF64
   AArch64, bounded PT_LOAD segments, and any PT_INTERP loader present inside
   the same rootfs. Record hashes in text/JSON only. **Never execute** extracted
   binaries on the CI host or upload the rootfs.
4. Keep the production-style `boot.img` flagged as not RAM-only:
   `ramdisk_size=0` and `root=PARTLABEL=jz08-unconfigured-rootfs`.
5. Keep all images off Releases and off published CI artifacts.

## Independent hardware-dependent gates still blocking any boot trial

- Obtain a verified JZ08 RAM map, bootloader load addresses and DTB memory
  ranges. A zero-sized DT memory node is not proof of valid RAM layout.
- Build and validate a **separate**, ephemeral initramfs with a non-persistent
  observable `/init` marker (UART/USB only after its transport is proven).
  No dependence on writing an eMMC `/cache` marker.
- Validate that the exact bootloader path accepts a RAM-only load without
  writing GPT, boot, recovery, modemst or any OEM partition.
- Define a reliable power-cycle recovery and an independently observable
  success/failure criterion before a user is asked to test anything.
- Never substitute MF68E GPT, `flash.sh`, p14 rootfs, or a guessed LCD/GPIO.

**Decision:** passing the new offline userspace check strengthens the rootfs
audit only. It does not remove any hardware gate or authorize flashing.
