"""Build deterministic FAT16/FAT32/exFAT recovery fixtures without physical disks.

These files are deliberately tiny synthetic filesystems, not user data. exFAT
structures follow Microsoft's public exFAT 1.00 specification; FAT structures
follow Microsoft's FAT specification. No filesystem repair or mounting is used.
"""
from pathlib import Path
import hashlib
import json
import math
import struct


FILES = {
    "readme.txt": b"Synthetic recovery fixture. Never real user data.\r\n",
    "Документы/Отчёт 2026.txt": "Проверка восстановления имён и папок.\r\n".encode("utf-8"),
    "Документы/Вложенная папка/данные.bin": bytes(range(256)) * 53 + b"THE END\x00\xff",
    "Документы/same.txt": b"first distinct content\n",
    "Фото/same.txt": b"second distinct content\n",
    "Фото/empty.txt": b"",
}
DIRECTORIES = ["", "Документы", "Документы/Вложенная папка", "Фото"]
DATE = ((2026 - 1980) << 9) | (10 << 5) | 15


def pack(data, offset, fmt, *values):
    struct.pack_into("<" + fmt, data, offset, *values)


def short_name(name, index):
    if name in (".", ".."):
        return name.encode().ljust(11, b" ")
    suffix = name.rsplit(".", 1)[1].upper()[:3] if "." in name else ""
    return ("FILE%04d" % index).encode() + suffix.encode().ljust(3, b" ")


def fat_entry(name, index, cluster, size, directory=False):
    short = short_name(name, index)
    normal = bytearray(32)
    normal[:11] = short
    normal[11] = 0x10 if directory else 0x20
    pack(normal, 14, "HHH", 0, DATE, DATE)
    pack(normal, 20, "H", cluster >> 16)
    pack(normal, 22, "HHHI", 0, DATE, cluster & 0xFFFF, size)
    if name in (".", ".."):
        return normal
    checksum = 0
    for byte in short:
        checksum = (((checksum & 1) << 7) + (checksum >> 1) + byte) & 255
    raw = name.encode("utf-16le") + b"\0\0"
    count = math.ceil(len(raw) / 26)
    raw = raw.ljust(count * 26, b"\xff")
    entries = bytearray()
    for ordinal in reversed(range(1, count + 1)):
        e = bytearray(32)
        e[0] = ordinal | (0x40 if ordinal == count else 0)
        e[11] = 0x0F
        e[13] = checksum
        chunk = raw[(ordinal - 1) * 26:ordinal * 26]
        e[1:11], e[14:26], e[28:32] = chunk[:10], chunk[10:22], chunk[22:26]
        entries.extend(e)
    entries.extend(normal)
    return entries


def children(path):
    dirs = [(x, True) for x in DIRECTORIES[1:] if x.rpartition("/")[0] == path]
    files = [(x, False) for x in FILES if x.rpartition("/")[0] == path]
    return dirs + files


def make_fat(bits):
    sectors = 32768 if bits == 16 else 131072
    reserved, fat_sectors, root_entries = (1, 128, 512) if bits == 16 else (32, 1024, 0)
    root_sectors = root_entries * 32 // 512
    data_sector = reserved + fat_sectors * 2 + root_sectors
    cluster_count = sectors - data_sector
    assert (4085 <= cluster_count < 65525) if bits == 16 else cluster_count >= 65525
    image = bytearray(sectors * 512)
    boot = bytearray(512)
    boot[:11] = b"\xeb\x58\x90MSDOS5.0"
    pack(boot, 11, "HBHBHHBHHHII", 512, 1, reserved, 2, root_entries,
         sectors if sectors < 65536 else 0, 0xF8, fat_sectors if bits == 16 else 0,
         63, 255, 0, sectors if sectors >= 65536 else 0)
    if bits == 16:
        boot[36], boot[38] = 0x80, 0x29
        pack(boot, 39, "I", 0xF16A0001)
        boot[43:54], boot[54:62] = b"RECOVERY16 ", b"FAT16   "
    else:
        pack(boot, 36, "IHHIHH", fat_sectors, 0, 0, 2, 1, 6)
        boot[64], boot[66] = 0x80, 0x29
        pack(boot, 67, "I", 0xF32A0001)
        boot[71:82], boot[82:90] = b"RECOVERY32 ", b"FAT32   "
    boot[510:512] = b"\x55\xaa"
    image[:512] = boot
    fat = bytearray(fat_sectors * 512)
    fmt = "H" if bits == 16 else "I"
    end = 0xFFFF if bits == 16 else 0x0FFFFFFF
    pack(fat, 0, fmt, 0xFFF8 if bits == 16 else 0x0FFFFFF8)
    pack(fat, bits // 8, fmt, end)
    next_cluster = 2
    allocations = {}

    def alloc(path, count, fragment=False):
        nonlocal next_cluster
        seq = []
        for _ in range(count):
            seq.append(next_cluster)
            next_cluster += 2 if fragment else 1
        allocations[path] = seq
        for n, cluster in enumerate(seq):
            pack(fat, cluster * (bits // 8), fmt, seq[n + 1] if n + 1 < len(seq) else end)
        return seq

    for path in DIRECTORIES:
        allocations[path] = [] if bits == 16 and not path else alloc(path, 2)
    for path, payload in FILES.items():
        alloc(path, math.ceil(len(payload) / 512), path.endswith("данные.bin"))

    def store(seq, payload):
        for n, cluster in enumerate(seq):
            offset = (data_sector + cluster - 2) * 512
            chunk = payload[n * 512:(n + 1) * 512]
            image[offset:offset + len(chunk)] = chunk

    for path, payload in FILES.items():
        store(allocations[path], payload)
    for path in DIRECTORIES:
        body = bytearray()
        if path:
            body.extend(fat_entry(".", 0, allocations[path][0], 0, True))
            parent = path.rpartition("/")[0]
            parent_cluster = allocations[parent][0] if parent and allocations[parent] else 0
            body.extend(fat_entry("..", 0, parent_cluster, 0, True))
        for index, (child, directory) in enumerate(children(path), 1):
            seq = allocations[child]
            body.extend(fat_entry(child.rsplit("/", 1)[-1], index,
                                  seq[0] if seq else 0, 0 if directory else len(FILES[child]), directory))
        assert len(body) < (root_sectors * 512 if bits == 16 and not path else 1024)
        if bits == 16 and not path:
            root_start = (reserved + 2 * fat_sectors) * 512
            image[root_start:root_start + len(body)] = body
        else:
            store(allocations[path], body)
    for copy in range(2):
        start = (reserved + copy * fat_sectors) * 512
        image[start:start + len(fat)] = fat
    if bits == 32:
        fsinfo = bytearray(512)
        pack(fsinfo, 0, "I", 0x41615252)
        pack(fsinfo, 484, "IIII", 0x61417272, cluster_count - next_cluster + 2, next_cluster, 0)
        pack(fsinfo, 508, "I", 0xAA550000)
        image[512:1024] = fsinfo
        image[6 * 512:7 * 512] = boot
        image[7 * 512:8 * 512] = fsinfo
    return image


def rotate_checksum(data, width=16, skip=()):
    value = 0
    mask = (1 << width) - 1
    for index, byte in enumerate(data):
        if index not in skip:
            value = (((value & 1) << (width - 1)) + (value >> 1) + byte) & mask
    return value


def exfat_entries(name, cluster, length, directory, contiguous=True):
    raw = name.encode("utf-16le")
    names = math.ceil(len(raw) / 30)
    entries = bytearray((2 + names) * 32)
    entries[0:2] = bytes([0x85, 1 + names])
    pack(entries, 4, "H", 0x10 if directory else 0x20)
    for offset in (8, 12, 16):
        pack(entries, offset, "I", DATE << 16)
    entries[32:36] = bytes([0xC0, 3 if contiguous and cluster else 1, 0, len(raw) // 2])
    upper = "".join(chr(UPCASE[ord(char)]) for char in name).encode("utf-16le")
    pack(entries, 36, "H", rotate_checksum(upper))
    pack(entries, 40, "Q", length)
    pack(entries, 52, "IQ", cluster, length)
    for index in range(names):
        start = (2 + index) * 32
        entries[start] = 0xC1
        chunk = raw[index * 30:(index + 1) * 30]
        entries[start + 2:start + 2 + len(chunk)] = chunk
    pack(entries, 2, "H", rotate_checksum(entries, skip=(2, 3)))
    return entries


UPCASE = [ord(s) if len(s := chr(x).upper()) == 1 and ord(s) <= 65535 else x for x in range(65536)]


def make_exfat():
    sectors, fat_sector, fat_length, heap, cluster_size = 65536, 24, 64, 88, 4096
    cluster_count = (sectors - heap) // 8
    image = bytearray(sectors * 512)
    fat = bytearray(fat_length * 512)
    pack(fat, 0, "II", 0xFFFFFFF8, 0xFFFFFFFF)
    bitmap = bytearray(math.ceil(cluster_count / 8))
    allocations = {}
    next_cluster = 2

    def alloc(path, count, fragment=False, chain=False):
        nonlocal next_cluster
        seq = []
        for _ in range(count):
            seq.append(next_cluster)
            bitmap[(next_cluster - 2) // 8] |= 1 << ((next_cluster - 2) % 8)
            next_cluster += 2 if fragment else 1
        if chain:
            for n, cluster in enumerate(seq):
                pack(fat, cluster * 4, "I", seq[n + 1] if n + 1 < len(seq) else 0xFFFFFFFF)
        allocations[path] = seq
        return seq

    alloc("", 1, chain=True)
    bitmap_clusters = alloc("$Bitmap", math.ceil(len(bitmap) / cluster_size), chain=True)
    upper_data = struct.pack("<65536H", *UPCASE)
    upper_clusters = alloc("$UpCase", math.ceil(len(upper_data) / cluster_size), chain=True)
    for path in DIRECTORIES[1:]:
        alloc(path, 1)
    for path, data in FILES.items():
        fragment = path.endswith("данные.bin")
        alloc(path, math.ceil(len(data) / cluster_size), fragment, fragment)

    def store(seq, data):
        for n, cluster in enumerate(seq):
            offset = heap * 512 + (cluster - 2) * cluster_size
            chunk = data[n * cluster_size:(n + 1) * cluster_size]
            image[offset:offset + len(chunk)] = chunk

    for path, data in FILES.items():
        store(allocations[path], data)
    store(bitmap_clusters, bitmap)
    store(upper_clusters, upper_data)
    for path in DIRECTORIES:
        body = bytearray()
        if not path:
            allocation_entry = bytearray(32)
            allocation_entry[0] = 0x81
            pack(allocation_entry, 20, "IQ", bitmap_clusters[0], len(bitmap))
            upcase_entry = bytearray(32)
            upcase_entry[0] = 0x82
            pack(upcase_entry, 4, "I", rotate_checksum(upper_data, 32))
            pack(upcase_entry, 20, "IQ", upper_clusters[0], len(upper_data))
            label_entry = bytearray(32)
            label_entry[:2] = bytes([0x83, 8])
            label_entry[2:18] = "RECOVERY".encode("utf-16le")
            body.extend(allocation_entry + upcase_entry + label_entry)
        for child, directory in children(path):
            seq = allocations[child]
            body.extend(exfat_entries(child.rsplit("/", 1)[-1], seq[0] if seq else 0,
                                      cluster_size if directory else len(FILES[child]),
                                      directory, not child.endswith("данные.bin")))
        assert len(body) < cluster_size
        store(allocations[path], body)
    image[fat_sector * 512:(fat_sector + fat_length) * 512] = fat
    boot = bytearray(11 * 512)
    boot[:11] = b"\xeb\x76\x90EXFAT   "
    pack(boot, 64, "QQIIIIIIHHBBBBB", 0, sectors, fat_sector, fat_length, heap,
         cluster_count, 2, 0xEFA70001, 0x0100, 0, 9, 3, 1, 0x80, 1)
    boot[510:512] = b"\x55\xaa"
    for sector in range(1, 9):
        pack(boot, sector * 512 + 508, "I", 0xAA550000)
    checksum = rotate_checksum(boot, 32, (106, 107, 112))
    region = boot + struct.pack("<128I", *([checksum] * 128))
    image[:len(region)] = region
    image[12 * 512:12 * 512 + len(region)] = region
    return image


def mbr_wrapper(data, partition_type):
    image = bytearray(2048 * 512)
    image[446:462] = struct.pack("<B3sB3sII", 0, b"\xfe\xff\xff", partition_type,
                                 b"\xfe\xff\xff", 2048, len(data) // 512)
    image[510:512] = b"\x55\xaa"
    image.extend(data)
    image.extend(bytes(512))
    return image


def make_adversarial_fat16():
    """Intentionally invalid names test safe export, not format acceptance."""
    original_files = FILES.copy()
    original_directories = DIRECTORIES.copy()
    extra = {
        "Folder/inside.txt": b"case collision directory content\n",
        "FOLDER": b"case collision file content\n",
        "CON.txt": b"reserved DOS device name\n",
        "trailing.": b"trailing dot name\n",
        "trailing ": b"trailing space name\n",
        r"..\escape.txt": b"backslash traversal must stay within destination\n",
        "SAME.TXT": b"live same name content\n",
        "GONE.TXT": b"deleted same name content\n",
    }
    try:
        FILES.update(extra)
        DIRECTORIES.append("Folder")
        data = make_fat(16)
        root_start = 257 * 512
        root = data[root_start:root_start + 32 * 512]
        deleted_number = [p for p, d in children("")].index("GONE.TXT") + 1
        alias = short_name("GONE.TXT", deleted_number)
        index = root.find(alias)
        assert index >= 32 and root[index - 32 + 11] == 0x0F
        replacement = fat_entry("SAME.TXT", deleted_number,
                                struct.unpack_from("<H", root, index + 26)[0],
                                len(extra["GONE.TXT"]))
        assert len(replacement) == 64
        replacement[0] = replacement[32] = 0xE5
        data[root_start + index - 32:root_start + index + 32] = replacement
        return data, extra
    finally:
        FILES.clear()
        FILES.update(original_files)
        DIRECTORIES[:] = original_directories


