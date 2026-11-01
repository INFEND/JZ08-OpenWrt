"""Strict offline FDT root-compatible verification. No hardware assumptions."""
import struct


class FDTError(ValueError):
    pass


def verify_jz08_fdt(data):
    """Validate FDT structure and the root compatible property, not stray bytes.

    This proves only the DTB's structural identity. It does not establish that
    GPIO, RAM, LCD, modem or Wi-Fi wiring matches physical JZ08 hardware.
    """
    def need(ok, why):
        if not ok:
            raise FDTError("invalid JZ08 FDT: " + why)

    need(len(data) >= 40, "truncated header")
    (magic, total, struct_off, strings_off, reserve_off, version,
     last_compat, _boot_cpuid, strings_len, struct_len) = struct.unpack_from(">10I", data)
    need(magic == 0xD00DFEED, "bad FDT magic")
    need(total == len(data) and total <= 8 * 1024 * 1024, "invalid FDT total size")
    need(16 <= version <= 17 and last_compat <= 16, "unsupported FDT version")
    need(struct_off % 4 == 0 and strings_off % 4 == 0 and reserve_off % 8 == 0,
         "misaligned FDT block")
    need(reserve_off >= 40 and struct_off >= reserve_off + 16,
         "invalid reservation map location")
    need(struct_len >= 8 and strings_len > 0 and struct_off + struct_len <= total
         and strings_off + strings_len <= total, "FDT block outside file")
    need(struct_off + struct_len <= strings_off or strings_off + strings_len <= struct_off,
         "overlapping FDT blocks")
    need(reserve_off < struct_off and reserve_off < strings_off,
         "reservation map overlaps blocks")

    cursor = reserve_off
    reserve_end = min(struct_off, strings_off)
    while True:
        need(cursor + 16 <= reserve_end, "unterminated memory reservation map")
        address, size = struct.unpack_from(">QQ", data, cursor)
        cursor += 16
        if address == 0 and size == 0:
            break

    strings = data[strings_off:strings_off + strings_len]
    struct_end = struct_off + struct_len
    cursor = struct_off
    depth = 0
    root_compatible = None
    saw_root = False
    saw_end = False
    while cursor < struct_end:
        need(cursor + 4 <= struct_end, "truncated structure token")
        token = struct.unpack_from(">I", data, cursor)[0]
        cursor += 4
        if token == 1:  # FDT_BEGIN_NODE
            end = data.find(b"\x00", cursor, struct_end)
            need(end >= 0, "unterminated node name")
            if depth == 0:
                need(not saw_root and end == cursor, "missing or duplicate root node")
                saw_root = True
            cursor = (end + 4) & ~3
            need(cursor <= struct_end, "node name outside structure")
            depth += 1
        elif token == 2:  # FDT_END_NODE
            need(depth > 0, "unmatched END_NODE")
            depth -= 1
        elif token == 3:  # FDT_PROP
            need(depth > 0 and cursor + 8 <= struct_end, "property outside node")
            length, name_off = struct.unpack_from(">II", data, cursor)
            cursor += 8
            need(name_off < len(strings), "property name outside string table")
            name_end = strings.find(b"\x00", name_off)
            need(name_end >= 0, "unterminated property name")
            need(length <= struct_end - cursor, "property value outside structure")
            name = strings[name_off:name_end]
            if depth == 1 and name == b"compatible":
                need(root_compatible is None, "duplicate root compatible")
                value = data[cursor:cursor + length]
                need(len(value) > 1 and value.endswith(b"\x00"),
                     "invalid root compatible string list")
                entries = value[:-1].split(b"\x00")
                need(all(entries), "empty root compatible entry")
                root_compatible = entries
            cursor = (cursor + length + 3) & ~3
        elif token == 4:  # FDT_NOP
            continue
        elif token == 9:  # FDT_END
            need(saw_root and depth == 0 and cursor == struct_end,
                 "invalid FDT_END or trailing tokens")
            saw_end = True
            break
        else:
            raise FDTError("invalid JZ08 FDT: unknown structure token")
    need(saw_end, "missing FDT_END")
    need(root_compatible is not None
         and b"xarkon,jz08-3000-nkv" in root_compatible,
         "root compatible does not identify JZ08")
    try:
        names = [entry.decode("ascii") for entry in root_compatible]
    except UnicodeDecodeError as exc:
        raise FDTError("invalid JZ08 FDT: non-ASCII root compatible") from exc
    return {"root_compatible": names, "dtb_bytes": total,
            "fdt_structure_valid": True}
