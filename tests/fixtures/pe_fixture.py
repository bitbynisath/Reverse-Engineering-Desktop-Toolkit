"""Helper fixture generator for creating minimal valid PE binaries in memory/disk."""

import struct
from pathlib import Path


def create_minimal_pe(
    file_path: Path,
    is_64bit: bool = True,
    is_dll: bool = False,
    rwx_section: bool = False,
) -> Path:
    """Generate a clean, valid, standalone Portable Executable binary file for testing."""
    buf = bytearray(0x600)  # Total 1536 bytes

    # 1. DOS Header
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x40)  # e_lfanew -> 0x40

    # 2. PE Signature
    buf[0x40:0x44] = b"PE\x00\x00"

    # 3. File (COFF) Header
    machine = 0x8664 if is_64bit else 0x014C
    num_sections = 2
    timestamp = 0x60000000
    opt_size = 240 if is_64bit else 224
    chars = 0x0022  # EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    if is_dll:
        chars |= 0x2000  # IMAGE_FILE_DLL

    struct.pack_into(
        "<HHIIIHH",
        buf,
        0x44,
        machine,
        num_sections,
        timestamp,
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        opt_size,
        chars,
    )

    # 4. Optional Header
    opt_offset = 0x58
    magic = 0x020B if is_64bit else 0x010B
    entry_point = 0x1000
    image_base = 0x140000000 if is_64bit else 0x00400000
    section_align = 0x1000
    file_align = 0x200
    size_of_image = 0x3000
    size_of_headers = 0x200
    subsystem = 2  # WINDOWS_GUI
    dll_chars = 0x8160  # DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE
    num_rva_and_sizes = 16

    if is_64bit:
        # Standard fields (24 bytes)
        struct.pack_into("<HBBIIIIQ", buf, opt_offset, magic, 14, 0, 0x200, 0x200, 0, entry_point, 0x1000)
        # NT additional fields
        struct.pack_into("<QIIHHHHIIIIHHQQQQII", buf, opt_offset + 24,
            image_base, section_align, file_align, 6, 0, 0, 0, 6, 0, 0, size_of_image, size_of_headers,
            0, subsystem, dll_chars, 0x100000, 0x1000, 0x100000, 0x1000, 0, num_rva_and_sizes
        )
    else:
        struct.pack_into("<HBBIIIII", buf, opt_offset, magic, 14, 0, 0x200, 0x200, 0, entry_point, 0x1000)
        struct.pack_into("<IIIHHHHIIIIHHIIIIII", buf, opt_offset + 28,
            image_base, section_align, file_align, 6, 0, 0, 0, 6, 0, 0, size_of_image, size_of_headers,
            0, subsystem, dll_chars, 0x100000, 0x1000, 0x100000, 0x1000, 0, num_rva_and_sizes
        )

    # 5. Section Headers (at opt_offset + opt_size)
    sec_offset = opt_offset + opt_size

    # Section 1: .text
    text_chars = 0x60000020  # CODE | EXECUTE | READ
    if rwx_section:
        text_chars |= 0x80000000  # WRITE -> RWX
    buf[sec_offset : sec_offset + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIIIIIHHI", buf, sec_offset + 8,
        0x100, 0x1000, 0x200, 0x200, 0, 0, 0, 0, text_chars
    )

    # Section 2: .data
    sec2_offset = sec_offset + 40
    data_chars = 0xC0000040  # INITIALIZED_DATA | READ | WRITE
    buf[sec2_offset : sec2_offset + 8] = b".data\x00\x00\x00"
    struct.pack_into("<IIIIIIHHI", buf, sec2_offset + 8,
        0x100, 0x2000, 0x200, 0x400, 0, 0, 0, 0, data_chars
    )

    # 6. Section Data
    # .text at 0x200
    buf[0x200:0x400] = b"\x90" * 0x200  # NOP sled
    # .data at 0x400
    buf[0x400:0x600] = b"\x00" * 0x200

    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_bytes(buf)
    return file_path
