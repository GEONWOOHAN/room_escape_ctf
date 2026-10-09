import struct


def build_elf(text, rodata, text_base=0x400000, ro_base=0x600000):
    text_off = 0x1000
    ro_off = (text_off + len(text) + 0xfff) & ~0xfff
    shstr = b"\0.text\0.rodata\0.shstrtab\0"
    shstr_off = ro_off + len(rodata)
    shoff = (shstr_off + len(shstr) + 3) & ~3
    eh = bytearray(52)
    eh[:16] = b"\x7fELF\x01\x01\x01" + b"\0" * 9
    struct.pack_into("<HHIIIIIHHHHHH", eh, 16, 2, 8, 1, text_base, 52, shoff, 0x10001001, 52, 32, 2, 40, 4, 3)
    ph1 = struct.pack("<IIIIIIII", 1, text_off, text_base, text_base, len(text), len(text), 5, 0x1000)
    ph2 = struct.pack("<IIIIIIII", 1, ro_off, ro_base, ro_base, len(rodata), len(rodata), 4, 0x1000)
    blob = bytearray(eh + ph1 + ph2)
    blob.extend(b"\0" * (text_off - len(blob))); blob.extend(text)
    blob.extend(b"\0" * (ro_off - len(blob))); blob.extend(rodata); blob.extend(shstr)
    blob.extend(b"\0" * (shoff - len(blob)))
    blob.extend(b"\0" * 40)
    blob.extend(struct.pack("<IIIIIIIIII", 1, 1, 0x6, text_base, text_off, len(text), 0, 0, 16, 0))
    blob.extend(struct.pack("<IIIIIIIIII", 7, 1, 0x2, ro_base, ro_off, len(rodata), 0, 0, 16, 0))
    blob.extend(struct.pack("<IIIIIIIIII", 15, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0))
    return bytes(blob)
