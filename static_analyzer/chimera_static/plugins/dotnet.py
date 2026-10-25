""".NET assembly metadata from the CLR header with pefile: runtime version, metadata streams and the #US
(user string) heap, which is where .NET malware keeps its URLs, paths and commands. Types and methods are not
decompiled; that is reported as partial coverage of the managed code."""

from __future__ import annotations

import struct

MAX_USER_STRINGS = 300
MAX_STRING_CHARS = 300
COMIMAGE_FLAGS = {0x1: "il_only", 0x2: "32bit_required", 0x8: "strong_name_signed", 0x10: "native_entrypoint",
                  0x20000: "32bit_preferred"}


def _user_strings(heap: bytes) -> list[str]:
    out, off = [], 1
    while off < len(heap) and len(out) < MAX_USER_STRINGS:
        b = heap[off]
        if b & 0x80 == 0:
            length, off = b, off + 1
        elif b & 0xC0 == 0x80 and off + 1 < len(heap):
            length, off = ((b & 0x3F) << 8) | heap[off + 1], off + 2
        elif off + 3 < len(heap):
            length, off = ((b & 0x1F) << 24) | (heap[off + 1] << 16) | (heap[off + 2] << 8) | heap[off + 3], off + 4
        else:
            break
        if length == 0:
            continue
        raw = heap[off:off + length - 1]  # last byte is a flag
        off += length
        text = raw.decode("utf-16-le", "replace").strip()
        if len(text) >= 4:
            out.append(text[:MAX_STRING_CHARS])
    return out


def analyze_dotnet(pe) -> dict:
    """pe: a parsed pefile.PE. Returns the dotnet block (raises if there is no CLR header)."""
    clr_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
    if not clr_dir.VirtualAddress:
        raise ValueError("no CLR header")
    clr = pe.get_data(clr_dir.VirtualAddress, 72)
    major, minor, md_rva, md_size, flags, entry = struct.unpack_from("<HHIIII", clr, 4)
    md = pe.get_data(md_rva, md_size)
    if md[:4] != b"BSJB":
        raise ValueError("bad metadata signature")
    (vlen,) = struct.unpack_from("<I", md, 12)
    version = md[16:16 + vlen].split(b"\x00", 1)[0].decode("latin-1")
    off = 16 + vlen
    (nstreams,) = struct.unpack_from("<H", md, off + 2)
    off += 4
    streams = {}
    for _ in range(min(nstreams, 16)):
        s_off, s_size = struct.unpack_from("<II", md, off)
        name_end = md.index(b"\x00", off + 8)
        name = md[off + 8:name_end].decode("latin-1")
        streams[name] = (s_off, s_size)
        off = (name_end + 4) & ~3
    us = streams.get("#US")
    user_strings = _user_strings(md[us[0]:us[0] + us[1]]) if us else []
    return {"runtime": version, "clr_version": f"{major}.{minor}",
            "flags": [n for bit, n in COMIMAGE_FLAGS.items() if flags & bit],
            "entry_token": hex(entry) if not flags & 0x10 else None,
            "streams": {k: v[1] for k, v in streams.items()}, "user_strings": user_strings,
            "user_strings_truncated": len(user_strings) >= MAX_USER_STRINGS}
