#!/usr/bin/env python3
"""
wail -- "What Am I Looking at": identify filesystem signatures in block
devices and disk-image files.

Strictly read-only.  The target is opened with O_RDONLY and nothing in this
program ever issues a write; the only system calls made against the target
are open/fstat/lseek/read/ioctl(get-size)/close.

Pure standard library.  Python 3.8+.  Runs on macOS, Linux, *BSD and Windows.

Usage:
    wail.py [-j] [-o OFFSET] [--no-partitions] DEVICE_OR_IMAGE ...
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import stat
import struct
import sys
import uuid as _uuid

__version__ = "0.1.0"

ALIGN = 4096          # every read is done in whole, aligned 4 KiB blocks
MAX_DEPTH = 3         # partition table nesting (e.g. MBR -> BSD disklabel -> fs)

# --------------------------------------------------------------------------
# Low-level helpers
# --------------------------------------------------------------------------


def _u8(b, o):
    return b[o]


def _u16le(b, o):
    return struct.unpack_from("<H", b, o)[0]


def _u16be(b, o):
    return struct.unpack_from(">H", b, o)[0]


def _u32le(b, o):
    return struct.unpack_from("<I", b, o)[0]


def _u32be(b, o):
    return struct.unpack_from(">I", b, o)[0]


def _u64le(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def _u64be(b, o):
    return struct.unpack_from(">Q", b, o)[0]


def _cstr(b, enc="utf-8"):
    """NUL-terminated byte string -> str (best effort)."""
    return b.split(b"\0", 1)[0].decode(enc, "replace").strip()


def _utf16(b, order="le"):
    """NUL-terminated UTF-16 string -> str (best effort)."""
    s = b.decode("utf-16-" + order, "replace")
    return s.split("\0", 1)[0].strip()


def _uuid_be(b):
    """16 raw bytes (RFC 4122 / big-endian layout) -> canonical string."""
    return str(_uuid.UUID(bytes=bytes(b)))


def _uuid_le(b):
    """16 raw bytes in Microsoft/EFI mixed-endian GUID layout -> string."""
    return str(_uuid.UUID(bytes_le=bytes(b))).upper()


def human(n):
    """Human-readable size."""
    if n is None:
        return "?"
    units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]
    f = float(n)
    for u in units:
        if f < 1024 or u == units[-1]:
            return ("%d %s" % (f, u)) if u == "B" else ("%.1f %s" % (f, u))
        f /= 1024.0
    return str(n)


_HFS_EPOCH = _dt.datetime(1904, 1, 1)


def _ts(seconds, epoch=_dt.datetime(1970, 1, 1)):
    """Unix timestamps are UTC; classic HFS/HFS+ timestamps are local time."""
    if not seconds:
        return None
    try:
        when = (epoch + _dt.timedelta(seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, ValueError):
        return None
    return when + (" (local time)" if epoch is _HFS_EPOCH else " UTC")


def match(fstype, description, label=None, uuid=None, version=None,
          weak=False, kind="filesystem", **details):
    """Build a match record. `weak` matches are only reported when nothing
    stronger matched at the same offset."""
    return {
        "type": fstype,
        "description": description,
        "kind": kind,
        "label": label,
        "uuid": uuid,
        "version": version,
        "weak": weak,
        "details": {k: v for k, v in details.items() if v is not None and v != ""},
    }


# --------------------------------------------------------------------------
# Read-only, block-aligned reader
# --------------------------------------------------------------------------


class Reader:
    """Read-only access to a file or device.

    Reads are performed as aligned whole 4 KiB blocks (a requirement for raw
    devices such as macOS /dev/rdiskN and Windows \\\\.\\PhysicalDriveN) and
    cached, so probing is cheap and never touches more of the medium than
    necessary.  There is deliberately no write path in this class."""

    def __init__(self, path):
        self.path = path
        flags = os.O_RDONLY
        for name in ("O_BINARY", "O_CLOEXEC", "O_NOCTTY", "O_LARGEFILE"):
            flags |= getattr(os, name, 0)
        self.fd = os.open(path, flags)
        self._cache = {}
        self.size = self._probe_size()

    # -- lifecycle ---------------------------------------------------------
    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- size --------------------------------------------------------------
    def _probe_size(self):
        try:
            st = os.fstat(self.fd)
            if stat.S_ISREG(st.st_mode):
                return st.st_size
        except OSError:
            pass
        # Block / character devices: ask the OS.
        size = self._ioctl_size()
        if size:
            return size
        try:
            size = os.lseek(self.fd, 0, os.SEEK_END)
            os.lseek(self.fd, 0, os.SEEK_SET)
            if size > 0:
                return size
        except OSError:
            pass
        return 0  # unknown

    def _ioctl_size(self):
        plat = sys.platform
        try:
            if plat == "win32":
                import ctypes
                import msvcrt
                from ctypes import wintypes
                handle = msvcrt.get_osfhandle(self.fd)
                out = ctypes.c_longlong(0)
                ret = wintypes.DWORD(0)
                IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C
                ok = ctypes.windll.kernel32.DeviceIoControl(
                    wintypes.HANDLE(handle), IOCTL_DISK_GET_LENGTH_INFO,
                    None, 0, ctypes.byref(out), 8, ctypes.byref(ret), None)
                return out.value if ok else 0
            import fcntl
            if plat.startswith("linux"):
                buf = bytearray(8)
                fcntl.ioctl(self.fd, 0x80081272, buf)        # BLKGETSIZE64
                return struct.unpack("Q", buf)[0]
            if plat == "darwin":
                b1 = bytearray(4)
                b2 = bytearray(8)
                fcntl.ioctl(self.fd, 0x40046418, b1)         # DKIOCGETBLOCKSIZE
                fcntl.ioctl(self.fd, 0x40086419, b2)         # DKIOCGETBLOCKCOUNT
                return struct.unpack("I", b1)[0] * struct.unpack("Q", b2)[0]
            if plat.startswith(("freebsd", "dragonfly")):
                buf = bytearray(8)
                fcntl.ioctl(self.fd, 0x40086481, buf)        # DIOCGMEDIASIZE
                return struct.unpack("Q", buf)[0]
        except (OSError, ImportError, AttributeError, struct.error):
            pass
        return 0

    # -- reading -----------------------------------------------------------
    def _read_at(self, off, n):
        try:
            os.lseek(self.fd, off, os.SEEK_SET)
            buf = b""
            while len(buf) < n:
                chunk = os.read(self.fd, n - len(buf))
                if not chunk:
                    break
                buf += chunk
            return buf
        except OSError:
            return None

    def _block(self, off):
        b = self._cache.get(off)
        if b is None:
            b = self._read_at(off, ALIGN)
            if b is None:
                # Raw devices whose size is not a multiple of 4 KiB reject a
                # 4 KiB read at the very end; fall back to 512-byte sectors.
                b = b""
                for s in range(off, off + ALIGN, 512):
                    c = self._read_at(s, 512)
                    if not c:
                        break
                    b += c
            if len(self._cache) > 16384:   # ~64 MiB worst case
                self._cache.clear()
            self._cache[off] = b
        return b

    def read(self, off, n):
        """Return up to `n` bytes at absolute byte offset `off` (short at EOF)."""
        if off < 0 or n <= 0:
            return b""
        if self.size and off >= self.size:
            return b""
        start = off - (off % ALIGN)
        parts = []
        for blk in range(start, off + n, ALIGN):
            b = self._block(blk)
            parts.append(b)
            if len(b) < ALIGN:
                break
        data = b"".join(parts)
        return data[off - start: off - start + n]


# --------------------------------------------------------------------------
# Filesystem probes.  Each takes (reader, base_offset) and returns a match
# dict, a list of match dicts, or None.  Any exception (short read, bad
# struct) simply means "no match".
# --------------------------------------------------------------------------

# ---- Linux ---------------------------------------------------------------


def probe_ext(r, base):
    sb = r.read(base + 1024, 1024)
    if len(sb) < 1024 or _u16le(sb, 0x38) != 0xEF53:
        return None
    log_bs = _u32le(sb, 0x18)
    if log_bs > 6 or _u32le(sb, 0) == 0 or _u32le(sb, 0x20) == 0 or _u32le(sb, 0x4C) > 1:
        return None
    compat = _u32le(sb, 0x5C)
    incompat = _u32le(sb, 0x60)
    rocompat = _u32le(sb, 0x64)
    if incompat & 0x8:
        fstype, desc = "ext-journal", "external ext3/ext4 journal device"
    elif incompat & 0x1FFC0 or rocompat & 0x778:
        fstype, desc = "ext4", "ext4 filesystem"
    elif compat & 0x4:
        fstype, desc = "ext3", "ext3 filesystem"
    else:
        fstype, desc = "ext2", "ext2 filesystem"
    block_size = 1024 << log_bs
    blocks = _u32le(sb, 4)
    if incompat & 0x80:
        blocks |= _u32le(sb, 0x150) << 32
    state = _u16le(sb, 0x3A)
    states = []
    if state & 1:
        states.append("clean")
    if state & 2:
        states.append("errors detected")
    if incompat & 0x4:
        states.append("journal needs recovery")
    features = []
    if incompat & 0x40:
        features.append("extents")
    if incompat & 0x80:
        features.append("64bit")
    if rocompat & 0x400:
        features.append("metadata_csum")
    if incompat & 0x10000:
        features.append("encrypt")
    if compat & 0x4:
        features.append("has_journal")
    return match(
        fstype, desc,
        label=_cstr(sb[0x78:0x88]),
        uuid=_uuid_be(sb[0x68:0x78]),
        block_size=block_size,
        size=blocks * block_size,
        state=", ".join(states) or "not clean",
        last_mounted_on=_cstr(sb[0x88:0xC8]),
        last_write=_ts(_u32le(sb, 0x30)),
        features=", ".join(features) or None,
    )


def probe_xfs(r, base):
    sb = r.read(base, 512)
    if sb[:4] != b"XFSB":
        return None
    bs = _u32be(sb, 4)
    vnum = _u16be(sb, 100)
    ver = vnum & 0xF
    return match(
        "xfs", "XFS filesystem",
        label=_cstr(sb[108:120]),
        uuid=_uuid_be(sb[32:48]),
        version="v%d%s" % (ver, " (CRC-enabled)" if ver == 5 else ""),
        block_size=bs,
        sector_size=_u16be(sb, 102),
        inode_size=_u16be(sb, 104),
        size=_u64be(sb, 8) * bs,
    )


def probe_btrfs(r, base):
    sb = r.read(base + 0x10000, 0x1000)
    if len(sb) < 0x1000 or sb[0x40:0x48] != b"_BHRfS_M":
        return None
    return match(
        "btrfs", "Btrfs filesystem",
        label=_cstr(sb[0x12B:0x22B]),
        uuid=_uuid_be(sb[0x20:0x30]),
        size=_u64le(sb, 0x70),
        used=_u64le(sb, 0x78),
        sector_size=_u32le(sb, 0x90),
        node_size=_u32le(sb, 0x94),
        devices=_u64le(sb, 0x88),
        device_uuid=_uuid_be(sb[0x103:0x113]),
        generation=_u64le(sb, 0x48),
    )


def probe_f2fs(r, base):
    sb = r.read(base + 1024, 2048)
    if len(sb) < 1200 or _u32le(sb, 0) != 0xF2F52010:
        return None
    log_bs = _u32le(sb, 16)
    return match(
        "f2fs", "F2FS (Flash-Friendly) filesystem",
        label=_utf16(sb[124:124 + 1024]),
        uuid=_uuid_be(sb[108:124]),
        version="%d.%d" % (_u16le(sb, 4), _u16le(sb, 6)),
        block_size=1 << log_bs if log_bs < 32 else None,
        size=_u64le(sb, 36) << log_bs if log_bs < 32 else None,
    )


def probe_jfs(r, base):
    sb = r.read(base + 0x8000, 512)
    if sb[:4] != b"JFS1":
        return None
    bsize = _u32le(sb, 16)          # s_bsize (aggregate block size)
    pbsize = _u32le(sb, 24)         # s_pbsize (physical block size)
    return match(
        "jfs", "JFS (IBM Journaled File System)",
        label=_cstr(sb[152:168]),
        uuid=_uuid_be(sb[136:152]),
        version=str(_u32le(sb, 4)),
        block_size=bsize,
        size=_u64le(sb, 8) * pbsize if pbsize else None,
    )


def probe_reiserfs(r, base):
    for off in (0x10000, 0x2000):
        sb = r.read(base + off, 512)
        if len(sb) < 512:
            continue
        magic = sb[52:62]
        if magic.startswith(b"ReIsErFs"):
            ver, new = "3.5", False
        elif magic.startswith(b"ReIsEr2Fs"):
            ver, new = "3.6", True
        elif magic.startswith(b"ReIsEr3Fs"):
            ver, new = "3.6 (jr)", True
        else:
            continue
        bs = _u16le(sb, 44)
        return match(
            "reiserfs", "ReiserFS filesystem",
            label=_cstr(sb[0x64:0x74]) if new else None,
            uuid=_uuid_be(sb[0x54:0x64]) if new else None,
            version=ver,
            block_size=bs,
            size=_u32le(sb, 0) * bs,
            superblock_offset=off,
        )
    return None


def probe_reiser4(r, base):
    sb = r.read(base + 0x10000, 512)
    if sb[:7] != b"ReIsEr4":
        return None
    return match(
        "reiser4", "Reiser4 filesystem",
        label=_cstr(sb[36:52]),
        uuid=_uuid_be(sb[20:36]),
        block_size=_u16le(sb, 18),
    )


def probe_nilfs2(r, base):
    sb = r.read(base + 1024, 1024)
    if len(sb) < 256 or _u16le(sb, 6) != 0x3434:
        return None
    log = _u32le(sb, 20)
    if log > 10:
        return None
    return match(
        "nilfs2", "NILFS2 (log-structured) filesystem",
        label=_cstr(sb[168:248]),
        uuid=_uuid_be(sb[152:168]),
        version="%d.%d" % (_u32le(sb, 0), _u16le(sb, 4)),
        block_size=1024 << log,
        size=_u64le(sb, 32),
    )


_BCACHEFS_MAGIC = bytes.fromhex("c68573f666ce90a9d96a60cf803df7ef")


def probe_bcachefs(r, base):
    sb = r.read(base + 4096, 512)
    if len(sb) < 128 or sb[24:40] != _BCACHEFS_MAGIC:
        return None
    return match(
        "bcachefs", "bcachefs filesystem",
        label=_cstr(sb[72:104]),
        uuid=_uuid_be(sb[56:72]),
        version=str(_u16le(sb, 16)),
        internal_uuid=_uuid_be(sb[40:56]),
    )


def probe_erofs(r, base):
    sb = r.read(base + 1024, 128)
    if len(sb) < 128 or _u32le(sb, 0) != 0xE0F5E1E2:
        return None
    bits = sb[12]
    return match(
        "erofs", "EROFS (Enhanced Read-Only) filesystem",
        label=_cstr(sb[64:80]),
        uuid=_uuid_be(sb[48:64]),
        block_size=1 << bits if bits < 32 else None,
        size=(_u32le(sb, 36) << bits) if bits < 32 else None,
        build_time=_ts(_u64le(sb, 24)),
    )


def probe_ocfs2(r, base):
    for off in (0x1000, 0x2000, 0x4000):
        sb = r.read(base + off, 512)
        if sb[:6] != b"OCFSV2":
            continue
        s = 0xC0
        bits = _u32le(sb, s + 56)
        return match(
            "ocfs2", "OCFS2 (Oracle Cluster) filesystem",
            label=_cstr(sb[s + 80:s + 144]),
            uuid=_uuid_be(sb[s + 144:s + 160]),
            version="%d.%d" % (_u16le(sb, s), _u16le(sb, s + 2)),
            block_size=1 << bits if bits < 32 else None,
            cluster_size=1 << _u32le(sb, s + 60) if _u32le(sb, s + 60) < 32 else None,
            superblock_offset=off,
        )
    return None


def probe_gfs2(r, base):
    sb = r.read(base + 0x10000, 512)
    if len(sb) < 256 or _u32be(sb, 0) != 0x01161970:
        return None
    fmt = _u32be(sb, 24)
    if fmt == 1801:
        fstype, desc = "gfs2", "GFS2 (Global File System 2)"
    elif fmt == 1309:
        fstype, desc = "gfs", "GFS (Global File System 1)"
    else:
        return None
    return match(
        fstype, desc,
        label=_cstr(sb[156:220]),
        uuid=_uuid_be(sb[220:236]) if fstype == "gfs2" else None,
        block_size=_u32be(sb, 36),
        lock_protocol=_cstr(sb[92:156]),
    )


def probe_squashfs(r, base):
    sb = r.read(base, 96)
    if len(sb) < 96:
        return None
    if sb[:4] == b"hsqs":
        end, order = "<", "little-endian"
    elif sb[:4] == b"sqsh":
        end, order = ">", "big-endian"
    else:
        return None
    major, minor = struct.unpack_from(end + "HH", sb, 28)
    comp = {1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}
    details = {"byte_order": order}
    if major == 4:
        details["compression"] = comp.get(struct.unpack_from(end + "H", sb, 20)[0], "unknown")
        details["size"] = struct.unpack_from(end + "Q", sb, 40)[0]
        details["block_size"] = struct.unpack_from(end + "I", sb, 12)[0]
    return match("squashfs", "SquashFS (compressed read-only) filesystem",
                 version="%d.%d" % (major, minor), **details)


def probe_cramfs(r, base):
    sb = r.read(base, 64)
    if len(sb) < 64:
        return None
    if _u32le(sb, 0) == 0x28CD3D45:
        end = "<"
    elif _u32be(sb, 0) == 0x28CD3D45:
        end = ">"
    else:
        return None
    return match("cramfs", "cramfs (compressed ROM) filesystem",
                 label=_cstr(sb[48:64]),
                 size=struct.unpack_from(end + "I", sb, 4)[0],
                 byte_order="little-endian" if end == "<" else "big-endian")


def probe_romfs(r, base):
    sb = r.read(base, 32)
    if sb[:8] != b"-rom1fs-":
        return None
    return match("romfs", "romfs filesystem", label=_cstr(sb[16:32]),
                 size=_u32be(sb, 8))


def probe_minix(r, base):
    sb = r.read(base + 1024, 64)
    if len(sb) < 64:
        return None
    for end, order in (("<", "little-endian"), (">", "big-endian")):
        magic = struct.unpack_from(end + "H", sb, 16)[0]
        versions = {0x137F: ("1", 14), 0x138F: ("1", 30),
                    0x2468: ("2", 14), 0x2478: ("2", 30)}
        if magic in versions:
            ver, namelen = versions[magic]
            if struct.unpack_from(end + "H", sb, 4)[0] == 0 or \
               struct.unpack_from(end + "H", sb, 6)[0] == 0:
                continue
            return match("minix", "Minix filesystem", version=ver, weak=True,
                         byte_order=order, name_length=namelen)
        if struct.unpack_from(end + "H", sb, 24)[0] == 0x4D5A:
            return match("minix", "Minix filesystem", version="3", weak=True,
                         byte_order=order, block_size=struct.unpack_from(end + "H", sb, 28)[0])
    return None


def probe_ubifs(r, base):
    sb = r.read(base, 64)
    if len(sb) < 64 or _u32le(sb, 0) != 0x06101831 or sb[8] != 6:
        return None
    return match("ubifs", "UBIFS (UBI flash) filesystem", weak=True)


def probe_jffs2(r, base):
    sb = r.read(base, 16)
    if len(sb) < 16:
        return None
    for end, order in (("<", "little-endian"), (">", "big-endian")):
        magic, ntype = struct.unpack_from(end + "HH", sb, 0)
        if magic == 0x1985 and ntype in (0xE001, 0xE002, 0x2003, 0x2004, 0xE008, 0xE009, 0xE00A):
            return match("jffs2", "JFFS2 (flash) filesystem", weak=True, byte_order=order)
    return None


def probe_swap(r, base):
    for page in (4096, 8192, 16384, 65536):
        tail = r.read(base + page - 10, 10)
        if tail not in (b"SWAPSPACE2", b"SWAP-SPACE"):
            continue
        hdr = r.read(base + 1024, 64)
        if tail == b"SWAP-SPACE" or len(hdr) < 64:
            return match("swap", "Linux swap (old v0 format)", page_size=page)
        return match(
            "swap", "Linux swap",
            label=_cstr(hdr[28:44]),
            uuid=_uuid_be(hdr[12:28]),
            version=str(_u32le(hdr, 0)),
            page_size=page,
            size=(_u32le(hdr, 4) + 1) * page,
        )
    # Hibernation images reuse the swap area.
    for page in (4096, 8192, 16384, 65536):
        tail = r.read(base + page - 10, 10)
        if tail in (b"S1SUSPEND\0", b"S2SUSPEND\0", b"ULSUSPEND\0", b"TUXONICE\0\0", b"LINHIB0001"):
            return match("swsuspend", "Linux swap containing a hibernation image",
                         page_size=page, signature=_cstr(tail))
    return None


def probe_luks(r, base):
    hdr = r.read(base, 512)
    if hdr[:6] != b"LUKS\xba\xbe":
        return None
    ver = _u16be(hdr, 6)
    if ver == 1:
        return match("luks", "LUKS1 encrypted volume", kind="crypto",
                     version="1",
                     uuid=_cstr(hdr[168:208]),
                     cipher=_cstr(hdr[8:40]) + "-" + _cstr(hdr[40:72]),
                     hash=_cstr(hdr[72:104]))
    if ver == 2:
        return match("luks", "LUKS2 encrypted volume", kind="crypto",
                     version="2",
                     label=_cstr(hdr[24:72]),
                     uuid=_cstr(hdr[168:208]),
                     header_size=_u64be(hdr, 8),
                     checksum=_cstr(hdr[72:104]))
    return match("luks", "LUKS encrypted volume (unknown version %d)" % ver, kind="crypto")


def probe_bitlocker(r, base):
    sb = r.read(base, 512)
    if len(sb) < 512:
        return None
    if sb[3:11] == b"-FVE-FS-":
        return match("bitlocker", "BitLocker encrypted volume", kind="crypto",
                     uuid=_uuid_le(sb[160:176]) if sb[160:176] != b"\0" * 16 else None)
    if sb[0x1A8:0x1B0] == b"-FVE-FS-":
        return match("bitlocker", "BitLocker To Go encrypted volume (FAT32 discovery volume)",
                     kind="crypto")
    return None


def probe_lvm2(r, base):
    for s in range(4):
        lbl = r.read(base + 512 * s, 512)
        if len(lbl) < 512 or lbl[:8] != b"LABELONE" or lbl[24:32] != b"LVM2 001":
            continue
        pvh = _u32le(lbl, 20)
        raw = lbl[pvh:pvh + 32].decode("ascii", "replace")
        pretty = "-".join([raw[0:6], raw[6:10], raw[10:14], raw[14:18], raw[18:22], raw[22:26], raw[26:32]])
        return match("lvm2", "LVM2 physical volume", kind="container",
                     uuid=pretty, size=_u64le(lbl, pvh + 32), label_sector=s)
    return None


def probe_mdraid(r, base):
    levels = {-4: "multipath", -1: "linear", 0: "raid0", 1: "raid1", 4: "raid4",
              5: "raid5", 6: "raid6", 10: "raid10"}
    for off, ver in ((0, "1.1"), (4096, "1.2")):
        sb = r.read(base + off, 256)
        if len(sb) < 256 or _u32le(sb, 0) != 0xA92B4EFC or _u32le(sb, 4) != 1:
            continue
        level = struct.unpack_from("<i", sb, 72)[0]
        return match("mdraid", "Linux Software RAID (md) member, superblock %s" % ver,
                     kind="raid", version=ver,
                     label=_cstr(sb[32:64]),
                     uuid=_uuid_be(sb[16:32]),
                     level=levels.get(level, str(level)),
                     raid_disks=_u32le(sb, 92),
                     data_offset=_u64le(sb, 128) * 512,
                     data_size=_u64le(sb, 136) * 512)
    if r.size and r.size >= 0x10000 * 2:
        off = ((r.size // 0x10000) - 1) * 0x10000
        sb = r.read(base + off, 256)
        if len(sb) >= 256 and _u32le(sb, 0) == 0xA92B4EFC and _u32le(sb, 4) == 0:
            u = struct.pack("<IIII", _u32le(sb, 20), _u32le(sb, 52), _u32le(sb, 56), _u32le(sb, 60))
            level = struct.unpack_from("<i", sb, 28)[0]
            return match("mdraid", "Linux Software RAID (md) member, superblock 0.90",
                         kind="raid", version="0.90", uuid=_uuid_be(u),
                         level=levels.get(level, str(level)),
                         raid_disks=_u32le(sb, 40))
    return None


# ---- Windows -------------------------------------------------------------


def _ntfs_volume_info(r, base, bps, spc, mft_lcn, cpr):
    """Read $Volume (MFT record 3) for the volume name and NTFS version."""
    # Positive: clusters per record.  Negative: record size is 2^|n| bytes.
    rec_size = cpr * spc * bps if cpr > 0 else 1 << (-cpr)
    if not 256 <= rec_size <= 65536:
        return None, None, None
    rec = bytearray(r.read(base + mft_lcn * spc * bps + 3 * rec_size, rec_size))
    if rec[:4] != b"FILE":
        return None, None, None
    usa_ofs, usa_cnt = _u16le(rec, 4), _u16le(rec, 6)
    usa = rec[usa_ofs:usa_ofs + 2 * usa_cnt]
    for i in range(1, usa_cnt):
        pos = i * bps - 2
        if pos + 2 > len(rec):
            break
        if rec[pos:pos + 2] != usa[0:2]:
            return None, None, None
        rec[pos:pos + 2] = usa[2 * i:2 * i + 2]
    name = version = flags = None
    off = _u16le(rec, 20)
    while off + 24 <= len(rec):
        atype = _u32le(rec, off)
        if atype == 0xFFFFFFFF:
            break
        alen = _u32le(rec, off + 4)
        if alen == 0:
            break
        if rec[off + 8] == 0:  # resident
            vlen, voff = _u32le(rec, off + 16), _u16le(rec, off + 20)
            val = rec[off + voff:off + voff + vlen]
            if atype == 0x60:
                name = _utf16(val)
            elif atype == 0x70 and len(val) >= 12:
                version = "%d.%d" % (val[8], val[9])
                flags = _u16le(val, 10)
        off += alen
    return name, version, flags


def probe_ntfs(r, base):
    sb = r.read(base, 512)
    if len(sb) < 512 or sb[3:11] != b"NTFS    ":
        return None
    bps = _u16le(sb, 11)
    spc = sb[13]
    if bps not in (256, 512, 1024, 2048, 4096) or spc == 0 or _u16le(sb, 14) != 0 or sb[16] != 0:
        return None
    total = _u64le(sb, 40)
    mft = _u64le(sb, 48)
    cpr = struct.unpack_from("b", sb, 64)[0]
    name = version = flags = None
    try:
        name, version, flags = _ntfs_volume_info(r, base, bps, spc, mft, cpr)
    except (struct.error, IndexError, ValueError):
        pass
    state = None
    if flags is not None:
        state = "dirty (not cleanly unmounted)" if flags & 1 else "clean"
    return match(
        "ntfs", "NTFS filesystem",
        label=name,
        uuid="%016X" % _u64le(sb, 72),
        version=version,
        sector_size=bps,
        cluster_size=bps * spc,
        size=(total + 1) * bps,
        mft_offset=mft * spc * bps,
        state=state,
    )


def probe_refs(r, base):
    sb = r.read(base, 512)
    if len(sb) < 512 or sb[3:11] != b"ReFS\0\0\0\0" or sb[16:20] != b"FSRS":
        return None
    bps = _u32le(sb, 32)
    return match(
        "refs", "ReFS (Resilient File System)",
        version="%d.%d" % (sb[40], sb[41]),
        sector_size=bps,
        cluster_size=bps * _u32le(sb, 36),
        size=_u64le(sb, 24) * bps if bps else None,
    )


def _exfat_root(r, base, sb):
    bps = 1 << sb[108]
    spc = 1 << sb[109]
    heap = _u32le(sb, 88)
    root = _u32le(sb, 96)
    off = base + (heap + (root - 2) * spc) * bps
    data = r.read(off, min(bps * spc, 65536))
    label = guid = None
    for i in range(0, len(data) - 31, 32):
        e = data[i:i + 32]
        t = e[0]
        if t == 0:
            break
        if t == 0x83:
            label = e[2:2 + 2 * min(e[1], 11)].decode("utf-16-le", "replace").strip()
        elif t == 0xA0:
            guid = _uuid_le(e[16:32])
    return label, guid


def probe_exfat(r, base):
    sb = r.read(base, 512)
    if len(sb) < 512 or sb[3:11] != b"EXFAT   " or sb[11:64] != b"\0" * 53:
        return None
    if not (8 <= sb[108] <= 12) or sb[109] > 25:
        return None
    label = guid = None
    try:
        label, guid = _exfat_root(r, base, sb)
    except (struct.error, IndexError, ValueError):
        pass
    bps = 1 << sb[108]
    return match(
        "exfat", "exFAT filesystem",
        label=label,
        uuid="%04X-%04X" % (_u32le(sb, 100) >> 16, _u32le(sb, 100) & 0xFFFF),
        version="%d.%d" % (sb[105], sb[104]),
        sector_size=bps,
        cluster_size=bps << sb[109],
        size=_u64le(sb, 72) * bps,
        volume_guid=guid,
    )


def _fat_root_label(r, base, sb, bps, spc, reserved, nfats, fat_size, root_entries, is32):
    root_dir_sectors = (root_entries * 32 + bps - 1) // bps
    if is32:
        first_data = reserved + nfats * fat_size + root_dir_sectors
        root_cluster = _u32le(sb, 44)
        off = base + (first_data + (root_cluster - 2) * spc) * bps
        length = spc * bps
    else:
        off = base + (reserved + nfats * fat_size) * bps
        length = root_dir_sectors * bps
    data = r.read(off, min(length, 65536))
    for i in range(0, len(data) - 31, 32):
        e = data[i:i + 32]
        if e[0] == 0:
            break
        if e[0] == 0xE5:
            continue
        if e[11] & 0x3F == 0x08:
            return e[:11].decode("cp437", "replace").rstrip()
    return None


def probe_fat(r, base):
    sb = r.read(base, 512)
    if len(sb) < 512:
        return None
    bps = _u16le(sb, 11)
    spc = sb[13]
    reserved = _u16le(sb, 14)
    nfats = sb[16]
    media = sb[21]
    if bps not in (512, 1024, 2048, 4096) or spc == 0 or spc & (spc - 1) or reserved == 0 \
            or nfats not in (1, 2) or (media != 0xF0 and media < 0xF8):
        return None
    if sb[0] not in (0xEB, 0xE9) and sb[510:512] != b"\x55\xAA":
        return None
    root_entries = _u16le(sb, 17)
    total = _u16le(sb, 19) or _u32le(sb, 32)
    fat_size = _u16le(sb, 22) or _u32le(sb, 36)
    if total == 0 or fat_size == 0:
        return None
    root_dir_sectors = (root_entries * 32 + bps - 1) // bps
    data_sectors = total - (reserved + nfats * fat_size + root_dir_sectors)
    if data_sectors <= 0:
        return None
    clusters = data_sectors // spc
    is32 = _u16le(sb, 22) == 0 and _u32le(sb, 36) != 0
    if is32 or clusters >= 65525:
        fstype, is32 = "fat32", True
    elif clusters >= 4085:
        fstype = "fat16"
    else:
        fstype = "fat12"
    if is32:
        ext_sig, serial_off, label_off, type_off = sb[66], 67, 71, 82
    else:
        ext_sig, serial_off, label_off, type_off = sb[38], 39, 43, 54
    serial = None
    label = None
    if ext_sig in (0x28, 0x29):
        s = _u32le(sb, serial_off)
        serial = "%04X-%04X" % (s >> 16, s & 0xFFFF)
        if ext_sig == 0x29:
            label = sb[label_off:label_off + 11].decode("cp437", "replace").rstrip()
            if label in ("NO NAME", ""):
                label = None
    try:
        root_label = _fat_root_label(r, base, sb, bps, spc, reserved, nfats, fat_size, root_entries, is32)
        if root_label:
            label = root_label
    except (struct.error, IndexError, ValueError):
        pass
    return match(
        fstype, fstype.upper()[:3] + fstype[3:] + " filesystem",
        label=label,
        uuid=serial,
        sector_size=bps,
        cluster_size=bps * spc,
        clusters=clusters,
        size=total * bps,
        oem_name=sb[3:11].decode("ascii", "replace").strip(),
        fs_type_field=sb[type_off:type_off + 8].decode("ascii", "replace").strip() if ext_sig == 0x29 else None,
    )


def probe_hpfs(r, base):
    sb = r.read(base + 0x2000, 16)
    if len(sb) < 16 or _u32le(sb, 0) != 0xF995E849 or _u32le(sb, 4) != 0xFA53E9C5:
        return None
    boot = r.read(base, 512)
    label = None
    if len(boot) >= 54 and boot[38] == 0x29:
        label = boot[43:54].decode("cp437", "replace").rstrip()
    return match("hpfs", "HPFS (OS/2 High Performance File System)", label=label,
                 version=str(sb[8]))


# ---- ZFS -----------------------------------------------------------------


def _zfs_nvlist(data):
    """Minimal XDR nvlist decoder: returns top-level scalar pairs."""
    out = {}
    if len(data) < 12 or data[0] != 1:      # NV_ENCODE_XDR
        return out
    pos = 12
    while pos + 8 <= len(data):
        enc, dec = struct.unpack_from(">ii", data, pos)
        if enc <= 0 and dec <= 0:
            break
        if enc < 16 or pos + enc > len(data):
            break
        p = pos + 8
        nlen = _u32be(data, p)
        p += 4
        name = data[p:p + nlen].decode("ascii", "replace")
        p += (nlen + 3) & ~3
        typ, nelem = struct.unpack_from(">ii", data, p)
        p += 8
        val = None
        try:
            if typ == 9 and nelem == 1:                      # string
                slen = _u32be(data, p)
                val = data[p + 4:p + 4 + slen].decode("utf-8", "replace")
            elif typ in (7, 8) and nelem == 1:               # int64/uint64
                val = struct.unpack_from(">q" if typ == 7 else ">Q", data, p)[0]
            elif typ in (5, 6) and nelem == 1:               # int32/uint32
                val = struct.unpack_from(">i" if typ == 5 else ">I", data, p)[0]
            elif typ == 21 and nelem == 1:                   # boolean value
                val = bool(_u32be(data, p))
        except struct.error:
            pass
        if val is not None:
            out[name] = val
        pos += enc
    return out


def probe_zfs(r, base):
    states = {0: "active", 1: "exported", 2: "destroyed", 3: "spare", 4: "L2 cache", 5: "uninitialized"}
    for lbl in (0, 0x40000):
        best_txg, order = None, None
        for slot in range(0, 128 * 1024, 1024):
            ub = r.read(base + lbl + 0x20000 + slot, 64)
            if len(ub) < 64:
                break
            if _u64le(ub, 0) == 0x00BAB10C:
                end = "<"
            elif _u64be(ub, 0) == 0x00BAB10C:
                end = ">"
            else:
                continue
            txg = struct.unpack_from(end + "Q", ub, 16)[0]
            if best_txg is None or txg > best_txg:
                best_txg, order = txg, ("little-endian" if end == "<" else "big-endian")
        if best_txg is None:
            continue
        nv = _zfs_nvlist(r.read(base + lbl + 0x4000, 0x1C000))
        ver = nv.get("version")
        return match(
            "zfs", "ZFS pool member (vdev label)", kind="filesystem",
            label=nv.get("name"),
            uuid=("%016x" % nv["pool_guid"]) if "pool_guid" in nv else None,
            version=("%d (feature flags)" % ver) if ver == 5000 else (str(ver) if ver is not None else None),
            pool_state=states.get(nv.get("state"), nv.get("state")),
            txg=best_txg,
            vdev_guid=("%016x" % nv["guid"]) if "guid" in nv else None,
            top_guid=("%016x" % nv["top_guid"]) if "top_guid" in nv else None,
            hostname=nv.get("hostname"),
            vdev_children=nv.get("vdev_children"),
            byte_order=order,
            label_offset=lbl,
        )
    return None


# ---- UFS -----------------------------------------------------------------


def probe_ufs(r, base):
    for sboff in (8192, 65536, 262144, 0):
        sb = r.read(base + sboff, 0x560)
        if len(sb) < 0x560:
            continue
        m_le, m_be = _u32le(sb, 0x55C), _u32be(sb, 0x55C)
        if m_le == 0x00011954:
            ver, end = "1", "<"
        elif m_be == 0x00011954:
            ver, end = "1", ">"
        elif m_le == 0x19540119:
            ver, end = "2", "<"
        elif m_be == 0x19540119:
            ver, end = "2", ">"
        else:
            continue
        bsize = struct.unpack_from(end + "I", sb, 48)[0]
        fsize = struct.unpack_from(end + "I", sb, 52)[0]
        if bsize == 0 or bsize & (bsize - 1) or bsize > 65536:
            continue
        flavor = {8192: "BSD/Sun UFS1 layout", 65536: "UFS2 layout",
                  262144: "piggyback layout", 0: "floppy layout"}[sboff]
        return match(
            "ufs", "UFS%s (Unix File System)" % ver,
            label=_cstr(sb[680:712]) if ver == "2" else None,
            version=ver,
            block_size=bsize,
            fragment_size=fsize,
            last_mounted_on=_cstr(sb[212:212 + 468]),
            byte_order="little-endian" if end == "<" else "big-endian",
            superblock_offset=sboff,
            layout=flavor,
        )
    return None


# ---- Apple ---------------------------------------------------------------


def _fletcher64_ok(block):
    if len(block) < 16 or len(block) % 4:
        return False
    words = struct.unpack_from("<%dI" % ((len(block) - 8) // 4), block, 8)
    s1 = s2 = 0
    for w in words:
        s1 = (s1 + w) % 0xFFFFFFFF
        s2 = (s2 + s1) % 0xFFFFFFFF
    c1 = 0xFFFFFFFF - ((s1 + s2) % 0xFFFFFFFF)
    c2 = 0xFFFFFFFF - ((s1 + c1) % 0xFFFFFFFF)
    return struct.pack("<II", c1, c2) == block[:8]


def _apfs_omap_lookup(r, base, bs, node_paddr, oid, xid, depth=0):
    """Look `oid` up in a physical object-map B-tree, newest version <= xid."""
    if depth > 16:
        return None
    node = r.read(base + node_paddr * bs, bs)
    if len(node) < bs or (_u32le(node, 24) & 0xFFFF) not in (2, 3):   # BTREE (root) / BTREE_NODE
        return None
    flags, level, nkeys = _u16le(node, 32), _u16le(node, 34), _u32le(node, 36)
    toff, tlen = _u16le(node, 40), _u16le(node, 42)
    toc = 56 + toff
    keys_start = toc + tlen
    val_end = bs - (40 if flags & 1 else 0)
    fixed = bool(flags & 4)
    best = None
    for i in range(nkeys):
        if fixed:
            koff, voff = struct.unpack_from("<HH", node, toc + 4 * i)
        else:
            koff, _klen, voff, _vlen = struct.unpack_from("<HHHH", node, toc + 8 * i)
        k = keys_start + koff
        k_oid, k_xid = struct.unpack_from("<QQ", node, k)
        if k_oid < oid or (k_oid == oid and k_xid <= xid):
            best = (k_oid, val_end - voff)
        elif k_oid > oid:
            break
    if best is None:
        return None
    k_oid, v = best
    if level == 0:
        if k_oid != oid:
            return None
        return _u64le(node, v + 8)                 # ov_paddr
    child = _u64le(node, v)
    return _apfs_omap_lookup(r, base, bs, child, oid, xid, depth + 1)


_APFS_ROLES = {0: "none", 1: "system", 2: "user", 4: "recovery", 8: "VM", 0x10: "preboot",
               0x20: "installer", 0x40: "data", 0x80: "baseband", 0xC0: "update",
               0x100: "xART", 0x140: "hardware", 0x180: "backup", 0x1C0: "reserved",
               0x200: "reserved", 0x240: "enterprise", 0x280: "reserved", 0x2C0: "prelogin"}


def _apfs_volume(r, base, bs, paddr):
    vsb = r.read(base + paddr * bs, bs)
    if len(vsb) < 1024 or vsb[32:36] != b"APSB":
        return None
    incompat = _u64le(vsb, 56)
    fs_flags = _u64le(vsb, 264)
    role = _u16le(vsb, 964)
    attrs = []
    attrs.append("case-insensitive" if incompat & 1 else "case-sensitive")
    if incompat & 0x20:
        attrs.append("sealed")
    attrs.append("unencrypted" if fs_flags & 1 else "encrypted")
    return {
        "name": _cstr(vsb[704:960]),
        "uuid": _uuid_be(vsb[240:256]),
        "role": _APFS_ROLES.get(role, "0x%x" % role),
        "attributes": ", ".join(attrs),
        "files": _u64le(vsb, 184),
        "directories": _u64le(vsb, 192),
        "allocated": _u64le(vsb, 224) * bs,
        "snapshots": _u64le(vsb, 216),
        "last_modified": _ts(_u64le(vsb, 256) // 1000000000),
    }


def probe_apfs(r, base):
    sb0 = r.read(base, 4096)
    if len(sb0) < 4096:
        return None
    if sb0[32:36] == b"APSB":
        return match("apfs-volume", "APFS volume superblock (bare, outside a container)",
                     label=_cstr(sb0[704:960]), uuid=_uuid_be(sb0[240:256]))
    if sb0[32:36] != b"NXSB":
        return None
    bs = _u32le(sb0, 36)
    if bs not in (4096, 8192, 16384, 32768, 65536):
        return None
    sb = sb0
    if bs != 4096:
        sb = r.read(base, bs)
    # Find the newest valid checkpoint superblock in the descriptor area.
    note = "block 0 copy only"
    try:
        desc_blocks = _u32le(sb0, 104)
        desc_base = _u64le(sb0, 112)
        if not desc_blocks & 0x80000000 and 0 < desc_blocks <= 4096:
            best_xid = _u64le(sb0, 16)
            for i in range(desc_blocks):
                blk = r.read(base + (desc_base + i) * bs, bs)
                if len(blk) < bs or (_u32le(blk, 24) & 0xFFFF) != 1 or blk[32:36] != b"NXSB":
                    continue
                xid = _u64le(blk, 16)
                if xid >= best_xid and _fletcher64_ok(blk):
                    best_xid, sb, note = xid, blk, "latest checkpoint"
    except (struct.error, IndexError):
        pass
    xid = _u64le(sb, 16)
    incompat = _u64le(sb, 64)
    features = _u64le(sb, 48)
    max_fs = _u32le(sb, 180)
    fs_oids = [_u64le(sb, 184 + 8 * i) for i in range(min(max_fs, 100))]
    fs_oids = [o for o in fs_oids if o]
    volumes = []
    try:
        omap = r.read(base + _u64le(sb, 160) * bs, bs)
        if len(omap) >= 64 and (_u32le(omap, 24) & 0xFFFF) == 0xB:
            tree = _u64le(omap, 48)
            for oid in fs_oids:
                paddr = _apfs_omap_lookup(r, base, bs, tree, oid, xid)
                if paddr:
                    v = _apfs_volume(r, base, bs, paddr)
                    if v:
                        volumes.append(v)
    except (struct.error, IndexError, ValueError, RecursionError):
        pass
    flags = []
    if incompat & 0x100:
        flags.append("Fusion")
    if features & 0x1:
        flags.append("defrag")
    return match(
        "apfs", "APFS container", kind="container",
        label=", ".join('"%s"' % v["name"] for v in volumes) or None,
        uuid=_uuid_be(sb[72:88]),
        version="%d" % (incompat & 0xFF) if incompat & 0xFF else None,
        block_size=bs,
        size=_u64le(sb, 40) * bs,
        checkpoint=note,
        xid=xid,
        flags=", ".join(flags) or None,
        volume_count=len(fs_oids),
        volumes=volumes or None,
    )


def _hfsplus_label(r, base, vh):
    bs = _u32be(vh, 40)
    cat_start = _u32be(vh, 272 + 16 + 0)      # catalogFile.extents[0].startBlock
    cat = base + cat_start * bs
    hdr = r.read(cat, 512)
    node_size = _u16be(hdr, 32)
    first_leaf = _u32be(hdr, 24)
    cmp_type = hdr[51]
    if node_size < 512 or node_size > 32768 or first_leaf == 0:
        return None, cmp_type
    leaf = r.read(cat + first_leaf * node_size, node_size)
    if len(leaf) < node_size or leaf[8] != 0xFF:   # kind == leaf (-1)
        return None, cmp_type
    off = _u16be(leaf, node_size - 2)
    parent = _u32be(leaf, off + 2)
    if parent != 1:
        return None, cmp_type
    nlen = _u16be(leaf, off + 6)
    name = leaf[off + 8:off + 8 + 2 * nlen].decode("utf-16-be", "replace")
    return name, cmp_type


def _probe_hfsplus_at(r, base, vh, wrapper=None):
    sig = vh[:2]
    version = _u16be(vh, 2)
    attrs = _u32be(vh, 4)
    bs = _u32be(vh, 40)
    if bs == 0 or bs & (bs - 1):
        return None
    label = cmp_type = None
    try:
        label, cmp_type = _hfsplus_label(r, base, vh)
    except (struct.error, IndexError, ValueError):
        pass
    if sig == b"HX":
        fstype, desc = "hfsx", "HFSX (case-sensitive HFS+)"
        if cmp_type == 0xCF:
            desc = "HFSX (HFS+ with case-insensitive compare)"
    else:
        fstype, desc = "hfsplus", "HFS+ (Mac OS Extended)"
    states = []
    if attrs & 0x2000:
        states.append("journaled")
    states.append("unmounted cleanly" if attrs & 0x100 else "mounted / not cleanly unmounted")
    if wrapper:
        desc += " inside an HFS wrapper"
    return match(
        fstype, desc,
        label=label,
        uuid=vh[80 + 24:80 + 32].hex(),
        version=str(version),
        block_size=bs,
        size=_u32be(vh, 44) * bs,
        files=_u32be(vh, 32),
        folders=_u32be(vh, 36),
        created=_ts(_u32be(vh, 16), _HFS_EPOCH),
        last_mounted_by=vh[8:12].decode("ascii", "replace"),
        state=", ".join(states),
        wrapper_label=wrapper,
    )


def probe_hfs(r, base):
    vh = r.read(base + 1024, 512)
    if len(vh) < 512:
        return None
    sig = vh[:2]
    if sig in (b"H+", b"HX"):
        return _probe_hfsplus_at(r, base, vh)
    if sig != b"BD":
        return None
    alblksiz = _u32be(vh, 0x14)
    if alblksiz == 0 or alblksiz % 512:
        return None
    nlen = vh[0x24]
    name = vh[0x25:0x25 + min(nlen, 27)].decode("mac-roman", "replace")
    embed = vh[0x7C:0x7E]
    if embed in (b"H+", b"HX"):
        off = _u16be(vh, 0x1C) * 512 + _u16be(vh, 0x7E) * alblksiz
        inner = r.read(base + off + 1024, 512)
        if len(inner) == 512 and inner[:2] == embed:
            m = _probe_hfsplus_at(r, base + off, inner, wrapper=name)
            if m:
                m["details"]["embedded_offset"] = off
                return m
    return match(
        "hfs", "HFS (Mac OS Standard)",
        label=name,
        block_size=alblksiz,
        size=_u16be(vh, 0x12) * alblksiz,
        created=_ts(_u32be(vh, 2), _HFS_EPOCH),
        files=_u32be(vh, 84),
        folders=_u32be(vh, 88),
    )


# ---- Optical / misc ------------------------------------------------------


def _udf_dstring(b):
    if not b or b[-1] == 0:
        return None
    n = b[-1]
    body = b[1:n]
    if b[0] == 8:
        return body.decode("latin-1", "replace").strip()
    if b[0] == 16:
        return body.decode("utf-16-be", "replace").strip()
    return None


def _udf_details(r, base):
    for bs in (2048, 512, 1024, 4096):
        avdp = r.read(base + 256 * bs, 512)
        if len(avdp) < 32 or _u16le(avdp, 0) != 2:
            continue
        vds_len, vds_loc = _u32le(avdp, 16), _u32le(avdp, 20)
        info = {"sector_size": bs}
        for i in range(min(vds_len // bs, 32)):
            d = r.read(base + (vds_loc + i) * bs, 512)
            if len(d) < 512:
                break
            tag = _u16le(d, 0)
            if tag == 1:        # Primary Volume Descriptor
                info["volume_id"] = _udf_dstring(d[24:56])
                info["volume_set_id"] = _udf_dstring(d[72:200])
            elif tag == 6:      # Logical Volume Descriptor
                info["label"] = _udf_dstring(d[84:212])
                rev = _u16le(d, 240)
                info["version"] = "%x.%02x" % (rev >> 8, rev & 0xFF)
                info["domain"] = _cstr(d[217:240])
            elif tag == 8:      # terminating descriptor
                break
        return info
    return {}


def _isostr(b, enc="ascii"):
    return b.decode(enc, "replace").strip(" \0") or None


def probe_iso_udf(r, base):
    """ISO 9660 and/or UDF.  Both live in the Volume Recognition Sequence
    starting at sector 16; the UDF descriptors follow the ISO terminator."""
    out = []
    iso = None
    udf_ids = set()
    for i in range(16, 80):
        d = r.read(base + i * 2048, 2048)
        if len(d) < 2048:
            break
        ident = d[1:6]
        if ident == b"CD001":
            t = d[0]
            if t == 1 and iso is None:
                iso = match(
                    "iso9660", "ISO 9660 filesystem",
                    label=_isostr(d[40:72]),
                    system_id=_isostr(d[8:40]),
                    size=_u32le(d, 80) * (_u16le(d, 128) or 2048),
                    publisher=_isostr(d[318:446]),
                    application=_isostr(d[574:702]),
                )
            elif t == 2 and iso is not None and d[88:91] in (b"%/@", b"%/C", b"%/E"):
                iso["details"]["joliet_label"] = _isostr(d[40:72], "utf-16-be")
            elif t == 0 and d[7:30] == b"EL TORITO SPECIFICATION" and iso is not None:
                iso["details"]["bootable"] = "El Torito"
        elif ident in (b"BEA01", b"NSR02", b"NSR03", b"TEA01", b"BOOT2"):
            udf_ids.add(ident.decode("ascii"))
        else:
            break
    if iso:
        out.append(iso)
    if "NSR02" in udf_ids or "NSR03" in udf_ids:
        info = {}
        try:
            info = _udf_details(r, base)
        except (struct.error, IndexError, ValueError):
            pass
        label = info.pop("label", None) or info.get("volume_id")
        version = info.pop("version", None)
        desc = "UDF (Universal Disk Format)" + (" bridged with ISO 9660" if iso else "")
        out.append(match("udf", desc, label=label, version=version, **info))
    return out or None


def probe_befs(r, base):
    sb = r.read(base + 512, 64)
    if len(sb) < 64:
        return None
    if _u32le(sb, 32) == 0x42465331:
        end = "<"
    elif _u32be(sb, 32) == 0x42465331:
        end = ">"
    else:
        return None
    return match("befs", "BeFS (BeOS / Haiku)", label=_cstr(sb[:32]),
                 block_size=struct.unpack_from(end + "I", sb, 40)[0])


def probe_vmfs(r, base):
    sb = r.read(base + 0x100000, 64)
    if len(sb) >= 8 and _u32le(sb, 0) == 0xC001D00D:
        return match("vmfs", "VMware VMFS filesystem",
                     version=str(_u32le(sb, 4)), kind="filesystem")
    vol = r.read(base + 0x200000, 64)
    if len(vol) >= 8 and _u32le(vol, 0) == 0xC001D00D:
        return match("vmfs-volume", "VMware VMFS volume (LVM) member", kind="container")
    return None


def probe_amiga(r, base):
    sb = r.read(base, 4)
    if sb[:3] == b"DOS" and sb[3] <= 7:
        kinds = {0: "OFS", 1: "FFS", 2: "OFS international", 3: "FFS international",
                 4: "OFS dircache", 5: "FFS dircache", 6: "OFS long names", 7: "FFS long names"}
        return match("affs", "Amiga %s filesystem" % kinds[sb[3]], weak=True)
    return None


# ---- Disk-image containers and archives (helps say "this is not raw") ----

_ARCHIVE_SIGS = [
    (0, b"\x1f\x8b", "gzip", "gzip-compressed data (decompress first)"),
    (0, b"BZh", "bzip2", "bzip2-compressed data (decompress first)"),
    (0, b"\xfd7zXZ\x00", "xz", "xz-compressed data (decompress first)"),
    (0, b"\x28\xb5\x2f\xfd", "zstd", "zstd-compressed data (decompress first)"),
    (0, b"PK\x03\x04", "zip", "ZIP archive (extract first)"),
    (0, b"7z\xbc\xaf\x27\x1c", "7z", "7-Zip archive (extract first)"),
    (0, b"Rar!\x1a\x07", "rar", "RAR archive (extract first)"),
    (257, b"ustar", "tar", "tar archive (extract first)"),
    (0, b"EVF\x09\x0d\x0a\xff\x00", "ewf", "Expert Witness / EnCase (E01) forensic image (mount with libewf / ewfmount)"),
    (0, b"LVF\x09\x0d\x0a\xff\x00", "ewf", "Expert Witness / EnCase logical (L01) image"),
    (0, b"AFF\r\n\x00", "aff", "Advanced Forensic Format image (mount with affuse)"),
]


def probe_images(r, base):
    if base != 0:
        return None
    hdr = r.read(0, 512)
    if len(hdr) < 16:
        return None
    out = []
    if hdr[:4] == b"QFI\xfb":
        out.append(match("qcow", "QEMU QCOW%d disk image (not raw; use qemu-img convert -O raw, or qemu-nbd)" % _u32be(hdr, 4),
                         kind="image", version=str(_u32be(hdr, 4)), virtual_size=_u64be(hdr, 24)))
    elif hdr[:4] == b"KDMV":
        out.append(match("vmdk", "VMware VMDK sparse extent (not raw; use qemu-img convert -O raw)",
                         kind="image", version=str(_u32le(hdr, 4)), virtual_size=_u64le(hdr, 12) * 512))
    elif hdr[:21] == b"# Disk DescriptorFile":
        out.append(match("vmdk", "VMware VMDK descriptor file (text; points at extent files)", kind="image"))
    elif hdr[:8] == b"vhdxfile":
        out.append(match("vhdx", "Hyper-V VHDX disk image (not raw; use qemu-img convert -O raw)", kind="image"))
    elif hdr[:8] == b"conectix":
        kinds = {2: "fixed", 3: "dynamic", 4: "differencing"}
        out.append(match("vhd", "Virtual PC / Hyper-V VHD disk image, %s (not raw at offset 0; use qemu-img convert -O raw)"
                         % kinds.get(_u32be(hdr, 60), "unknown type"), kind="image",
                         virtual_size=_u64be(hdr, 40)))
    elif _u32le(hdr, 0x40) == 0xBEDA107F:
        out.append(match("vdi", "VirtualBox VDI disk image (not raw; use qemu-img convert -O raw)",
                         kind="image", comment=_cstr(hdr[:64]), version="%d.%d" % (_u16le(hdr, 0x46), _u16le(hdr, 0x44))))
    elif hdr[:16] == b"WithoutFreeSpace":
        out.append(match("parallels", "Parallels disk image (not raw)", kind="image"))
    elif hdr[:4] == b"QED\0":
        out.append(match("qed", "QEMU QED disk image (not raw)", kind="image"))
    for off, sig, name, desc in _ARCHIVE_SIGS:
        if hdr[off:off + len(sig)] == sig:
            out.append(match(name, desc, kind="archive"))
            break
    # Trailers: fixed-size VHD footer and Apple DMG 'koly' block.
    if r.size and r.size > 1024:
        tail = r.read(r.size - 512, 512)
        if len(tail) == 512:
            if tail[:8] == b"conectix" and hdr[:8] != b"conectix":
                out.append(match("vhd", "fixed-size VHD footer present (raw data precedes it)",
                                 kind="image", virtual_size=_u64be(tail, 40)))
            if tail[:4] == b"koly":
                out.append(match("dmg", "Apple UDIF disk image (.dmg) trailer; data may be compressed "
                                 "(hdiutil attach, or dmg2img)", kind="image",
                                 version=str(_u32be(tail, 8))))
    return out or None


# Order matters only for display: the first non-weak match is the headline.
FS_PROBES = [
    probe_images, probe_luks, probe_bitlocker, probe_lvm2, probe_mdraid, probe_zfs,
    probe_apfs, probe_hfs, probe_ntfs, probe_refs, probe_exfat, probe_fat, probe_hpfs,
    probe_ext, probe_xfs, probe_btrfs, probe_f2fs, probe_jfs, probe_reiserfs,
    probe_reiser4, probe_nilfs2, probe_bcachefs, probe_erofs, probe_ocfs2, probe_gfs2,
    probe_ufs, probe_squashfs, probe_cramfs, probe_romfs, probe_befs, probe_iso_udf,
    probe_vmfs, probe_swap, probe_minix, probe_ubifs, probe_jffs2, probe_amiga,
]

# --------------------------------------------------------------------------
# Partition tables
# --------------------------------------------------------------------------

GPT_TYPES = {
    "C12A7328-F81F-11D2-BA4B-00A0C93EC93B": "EFI System",
    "21686148-6449-6E6F-744E-656564454649": "BIOS boot",
    "E3C9E316-0B5C-4DB8-817D-F92DF00215AE": "Microsoft Reserved",
    "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7": "Microsoft Basic Data",
    "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC": "Windows Recovery",
    "5808C8AA-7E8F-42E0-85D2-E1E90434CFB3": "Windows LDM metadata",
    "AF9B60A0-1431-4F62-BC68-3311714A69AD": "Windows LDM data",
    "E75CAF8F-F680-4CEE-AFA3-B001E56EFC2D": "Windows Storage Spaces",
    "0FC63DAF-8483-4772-8E79-3D69D8477DE4": "Linux filesystem",
    "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F": "Linux swap",
    "E6D6D379-F507-44C2-A23C-238F2A3DF928": "Linux LVM",
    "A19D880F-05FC-4D3B-A006-743F0F84911E": "Linux RAID",
    "933AC7E1-2EB4-4F13-B844-0E14E2AEF915": "Linux /home",
    "44479540-F297-41B2-9AF7-D131D5F0458A": "Linux root (x86)",
    "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709": "Linux root (x86-64)",
    "B921B045-1DF0-41C3-AF44-4C6F280D3FAE": "Linux root (ARM64)",
    "69DAD710-2CE4-4E58-B9BB-37ABC00A8F5B": "Linux root (ARM)",
    "BC13C2FF-59E6-4262-A352-B275FD6F7172": "Linux extended boot",
    "CA7D7CCB-63ED-4C53-861C-1742536059CC": "Linux LUKS",
    "8DA63339-0007-60C0-C436-083AC8230908": "Linux reserved",
    "48465300-0000-11AA-AA11-00306543ECAC": "Apple HFS+",
    "7C3457EF-0000-11AA-AA11-00306543ECAC": "Apple APFS",
    "55465300-0000-11AA-AA11-00306543ECAC": "Apple UFS",
    "52414944-0000-11AA-AA11-00306543ECAC": "Apple RAID",
    "52414944-5F4F-11AA-AA11-00306543ECAC": "Apple RAID (offline)",
    "426F6F74-0000-11AA-AA11-00306543ECAC": "Apple Boot (Recovery HD)",
    "4C616265-6C00-11AA-AA11-00306543ECAC": "Apple Label",
    "53746F72-6167-11AA-AA11-00306543ECAC": "Apple Core Storage",
    "69646961-6700-11AA-AA11-00306543ECAC": "Apple Diagnostics",
    "6A898CC3-1DD2-11B2-99A6-080020736631": "Solaris /usr or Apple/illumos ZFS",
    "6A82CB45-1DD2-11B2-99A6-080020736631": "Solaris boot",
    "6A85CF4D-1DD2-11B2-99A6-080020736631": "Solaris root",
    "6A87C46F-1DD2-11B2-99A6-080020736631": "Solaris swap",
    "6A8B642B-1DD2-11B2-99A6-080020736631": "Solaris backup",
    "6A945A3B-1DD2-11B2-99A6-080020736631": "Solaris reserved",
    "516E7CB4-6ECF-11D6-8FF8-00022D09712B": "FreeBSD data",
    "516E7CB5-6ECF-11D6-8FF8-00022D09712B": "FreeBSD swap",
    "516E7CB6-6ECF-11D6-8FF8-00022D09712B": "FreeBSD UFS",
    "516E7CB8-6ECF-11D6-8FF8-00022D09712B": "FreeBSD Vinum",
    "516E7CBA-6ECF-11D6-8FF8-00022D09712B": "FreeBSD ZFS",
    "83BD6B9D-7F41-11DC-BE0B-001560B84F0F": "FreeBSD boot",
    "74BA7DD9-A689-11E1-BD04-00E081286ACF": "FreeBSD nandfs",
    "49F48D32-B10E-11DC-B99B-0019D1879648": "NetBSD swap",
    "49F48D5A-B10E-11DC-B99B-0019D1879648": "NetBSD FFS",
    "49F48D82-B10E-11DC-B99B-0019D1879648": "NetBSD LFS",
    "2DB519C4-B10F-11DC-B99B-0019D1879648": "NetBSD concatenated",
    "824CC7A0-36A8-11E3-890A-952519AD3F61": "OpenBSD data",
    "AA31E02A-400F-11DB-9590-000C2911D1B8": "VMware VMFS",
    "9D275380-40AD-11DB-BF97-000C2911D1B8": "VMware diagnostic",
    "9198EFFC-31C0-11DB-8F78-000C2911D1B8": "VMware reserved",
    "FE3A2A5D-4F32-41A7-B725-ACCC3285A309": "ChromeOS kernel",
    "3CB8E202-3B7E-47DD-8A3C-7FF2A13CFCEC": "ChromeOS rootfs",
    "42465331-3BA3-10F1-802A-4861696B7521": "Haiku BeFS",
    "D3BFE2DE-3DAF-11DF-BA40-E3A556D89593": "Intel Fast Flash",
    "F4019732-066E-4E12-8273-346C5641494F": "Sony boot",
    "BFBFAFE7-A34F-448A-9A5B-6213EB736C22": "Lenovo boot",
    "A2A0D0EB-E5B9-3344-87C0-68B6B72699C7": "Microsoft Basic Data (byte-swapped, corrupt GUID)",
}

MBR_TYPES = {
    0x01: "FAT12", 0x04: "FAT16 <32M", 0x05: "Extended", 0x06: "FAT16", 0x07: "NTFS/exFAT/HPFS",
    0x0B: "FAT32 (CHS)", 0x0C: "FAT32 (LBA)", 0x0E: "FAT16 (LBA)", 0x0F: "Extended (LBA)",
    0x11: "Hidden FAT12", 0x12: "Compaq diagnostics", 0x14: "Hidden FAT16 <32M", 0x16: "Hidden FAT16",
    0x17: "Hidden NTFS", 0x1B: "Hidden FAT32", 0x1C: "Hidden FAT32 (LBA)", 0x1E: "Hidden FAT16 (LBA)",
    0x27: "Windows RE / hidden NTFS", 0x39: "Plan 9", 0x3C: "PartitionMagic recovery",
    0x41: "PPC PReP boot", 0x42: "Windows LDM (dynamic disk)", 0x4D: "QNX4.x", 0x52: "CP/M",
    0x63: "GNU HURD / SysV", 0x64: "Novell NetWare 286", 0x65: "Novell NetWare 386",
    0x70: "DiskSecure Multi-Boot", 0x75: "PC/IX", 0x80: "Old Minix", 0x81: "Minix / old Linux",
    0x82: "Linux swap / Solaris", 0x83: "Linux", 0x84: "OS/2 hidden / Intel hibernation",
    0x85: "Linux extended", 0x86: "NTFS volume set", 0x87: "NTFS volume set", 0x88: "Linux plaintext",
    0x8E: "Linux LVM", 0x93: "Amoeba", 0x9F: "BSD/OS", 0xA0: "Laptop hibernation", 0xA5: "FreeBSD",
    0xA6: "OpenBSD", 0xA7: "NeXTSTEP", 0xA8: "Darwin UFS", 0xA9: "NetBSD", 0xAB: "Darwin boot",
    0xAF: "HFS / HFS+", 0xB7: "BSDI fs", 0xB8: "BSDI swap", 0xBE: "Solaris boot", 0xBF: "Solaris",
    0xC1: "DRDOS/sec FAT12", 0xC4: "DRDOS/sec FAT16 <32M", 0xC6: "DRDOS/sec FAT16", 0xC7: "Syrinx",
    0xDA: "Non-FS data", 0xDB: "CP/M / CTOS", 0xDE: "Dell utility", 0xDF: "BootIt",
    0xE1: "DOS access", 0xE3: "DOS R/O", 0xE4: "SpeedStor", 0xE8: "LUKS", 0xEA: "Linux extended boot",
    0xEB: "BeOS/Haiku BeFS", 0xEE: "GPT protective", 0xEF: "EFI System (FAT)", 0xF0: "Linux/PA-RISC boot",
    0xF1: "SpeedStor", 0xF4: "SpeedStor", 0xF2: "DOS secondary", 0xFB: "VMware VMFS",
    0xFC: "VMware swap", 0xFD: "Linux RAID autodetect", 0xFE: "LANstep", 0xFF: "BBT",
}

BSD_FSTYPES = {0: "unused", 1: "swap", 2: "Version 6", 3: "Version 7", 4: "System V", 5: "4.1BSD",
               6: "Eighth Edition", 7: "4.2BSD FFS", 8: "MSDOS", 9: "4.4LFS", 10: "unknown",
               11: "HPFS", 12: "ISO9660", 13: "boot", 14: "vinum", 15: "raid", 16: "Filecore",
               17: "ext2fs", 18: "NTFS", 19: "RAID", 20: "ccd", 21: "jfs", 22: "HAMMER",
               23: "HAMMER2", 24: "UDF", 25: "APFS", 26: "SYSVBFS", 27: "ZFS", 28: "nandfs"}


def probe_gpt(r, base, size):
    for ss in (512, 4096):
        hdr = r.read(base + ss, 92)
        if len(hdr) < 92 or hdr[:8] != b"EFI PART":
            continue
        return _parse_gpt(r, base, ss, hdr, "primary")
    # Primary header gone?  Try the backup at the end of the disk.
    if size:
        for ss in (512, 4096):
            hdr = r.read(base + size - ss, 92)
            if len(hdr) >= 92 and hdr[:8] == b"EFI PART":
                return _parse_gpt(r, base, ss, hdr, "backup (primary header missing or damaged)")
    return None


def _parse_gpt(r, base, ss, hdr, which):
    entries_lba = _u64le(hdr, 72)
    nentries = _u32le(hdr, 80)
    esize = _u32le(hdr, 84)
    if esize < 128 or nentries > 1024:
        return None
    table = r.read(base + entries_lba * ss, nentries * esize)
    parts = []
    for i in range(nentries):
        e = table[i * esize:(i + 1) * esize]
        if len(e) < 128:
            break
        tguid = e[:16]
        if tguid == b"\0" * 16:
            continue
        tstr = _uuid_le(tguid)
        first, last, attrs = struct.unpack_from("<QQQ", e, 32)
        flags = []
        if attrs & 1:
            flags.append("required")
        if attrs & 2:
            flags.append("no-block-io")
        if attrs & 4:
            flags.append("legacy-bootable")
        if attrs & (1 << 60):
            flags.append("read-only")
        if attrs & (1 << 62):
            flags.append("hidden")
        if attrs & (1 << 63):
            flags.append("no-automount")
        parts.append({
            "index": i + 1,
            "name": _utf16(e[56:128]),
            "type": GPT_TYPES.get(tstr, "unknown type " + tstr),
            "type_guid": tstr,
            "uuid": _uuid_le(e[16:32]),
            "offset": base + first * ss,
            "size": (last - first + 1) * ss if last >= first else 0,
            "attributes": ", ".join(flags) or None,
        })
    return {
        "scheme": "gpt",
        "description": "GPT partition table (%s header)" % which,
        "sector_size": ss,
        "uuid": _uuid_le(hdr[56:72]),
        "revision": "%d.%d" % (_u16le(hdr, 10), _u16le(hdr, 8)),
        "usable_range": [_u64le(hdr, 40) * ss, (_u64le(hdr, 48) + 1) * ss],
        "entries": nentries,
        "partitions": parts,
    }


def probe_mbr(r, base, size):
    sb = r.read(base, 512)
    if len(sb) < 512 or sb[510:512] != b"\x55\xAA":
        return None
    raw = []
    for i in range(4):
        e = sb[446 + 16 * i:446 + 16 * (i + 1)]
        status, ptype = e[0], e[4]
        lba, count = struct.unpack_from("<II", e, 8)
        if ptype == 0 and lba == 0 and count == 0:
            continue
        if status not in (0x00, 0x80, 0x81) or ptype == 0 or count == 0:
            return None
        raw.append((i + 1, status, ptype, lba, count))
    if not raw:
        return None
    protective = any(t == 0xEE for _, _, t, _, _ in raw)
    parts = []
    for idx, status, ptype, lba, count in raw:
        parts.append({
            "index": idx,
            "type": MBR_TYPES.get(ptype, "unknown"),
            "type_id": "0x%02X" % ptype,
            "bootable": bool(status & 0x80),
            "offset": base + lba * 512,
            "size": count * 512,
        })
        if ptype in (0x05, 0x0F, 0x85):
            parts.extend(_walk_ebr(r, base, lba, count))
    return {
        "scheme": "mbr",
        "description": "MBR (DOS) partition table" + (" -- protective entry for GPT" if protective else ""),
        "sector_size": 512,
        "disk_signature": "%08X" % _u32le(sb, 440),
        "protective": protective,
        "partitions": parts,
    }


def _walk_ebr(r, base, ext_start, ext_count):
    out = []
    cur = ext_start
    seen = set()
    n = 5
    while cur not in seen and len(out) < 128:
        seen.add(cur)
        ebr = r.read(base + cur * 512, 512)
        if len(ebr) < 512 or ebr[510:512] != b"\x55\xAA":
            break
        e0 = ebr[446:462]
        e1 = ebr[462:478]
        t0 = e0[4]
        lba0, cnt0 = struct.unpack_from("<II", e0, 8)
        if t0 and cnt0:
            out.append({
                "index": n,
                "type": MBR_TYPES.get(t0, "unknown"),
                "type_id": "0x%02X" % t0,
                "bootable": bool(e0[0] & 0x80),
                "offset": base + (cur + lba0) * 512,
                "size": cnt0 * 512,
                "logical": True,
            })
            n += 1
        t1 = e1[4]
        lba1, cnt1 = struct.unpack_from("<II", e1, 8)
        if t1 in (0x05, 0x0F, 0x85) and cnt1:
            cur = ext_start + lba1
        else:
            break
    return out


def probe_apm(r, base, size):
    dd = r.read(base, 512)
    if len(dd) < 512:
        return None
    bs = 512
    if dd[:2] == b"ER":
        bs = _u16be(dd, 2) or 512
    pm = r.read(base + bs, 512)
    if len(pm) < 512 or pm[:2] != b"PM":
        return None
    count = _u32be(pm, 4)
    if count == 0 or count > 256:
        return None
    parts = []
    for i in range(count):
        e = r.read(base + bs * (i + 1), 512)
        if len(e) < 512 or e[:2] != b"PM":
            break
        ptype = _cstr(e[48:80])
        parts.append({
            "index": i + 1,
            "name": _cstr(e[16:48]),
            "type": ptype,
            "offset": base + _u32be(e, 8) * bs,
            "size": _u32be(e, 12) * bs,
            "skip_content": ptype in ("Apple_partition_map", "Apple_Driver43", "Apple_Driver_ATA",
                                      "Apple_Free", "Apple_Driver43_CD", "Apple_Driver_ATAPI",
                                      "Apple_FWDriver", "Apple_Driver_IOKit", "Apple_Patches"),
        })
    return {
        "scheme": "apm",
        "description": "Apple Partition Map",
        "sector_size": bs,
        "partitions": parts,
    }


def probe_disklabel(r, base, size):
    for off in (512, 64, 0):
        lbl = r.read(base + off, 512)
        if len(lbl) < 512 or _u32le(lbl, 0) != 0x82564557 or _u32le(lbl, 132) != 0x82564557:
            continue
        secsize = _u32le(lbl, 40) or 512
        npart = _u16le(lbl, 138)
        if npart > 22:
            continue
        parts = []
        for i in range(npart):
            e = lbl[148 + 16 * i:148 + 16 * (i + 1)]
            psize, poff = struct.unpack_from("<II", e, 0)
            fstype = e[12]
            if psize == 0 or fstype == 0:
                continue
            parts.append({
                "index": chr(ord("a") + i),
                "type": BSD_FSTYPES.get(fstype, "type %d" % fstype),
                "type_id": fstype,
                "offset": poff * secsize,          # usually absolute; fixed up in identify()
                "size": psize * secsize,
                "relative_offset": base + poff * secsize,
            })
        return {
            "scheme": "bsd",
            "description": "BSD disklabel",
            "sector_size": secsize,
            "label_offset": off,
            "disk_type": _cstr(lbl[8:24]),
            "pack_name": _cstr(lbl[24:40]),
            "partitions": parts,
        }
    return None


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------


def _run_probe(p, r, base):
    try:
        m = p(r, base)
    except (struct.error, IndexError, ValueError, UnicodeError, KeyError, ZeroDivisionError, OverflowError):
        return []
    if m is None:
        return []
    return m if isinstance(m, list) else [m]


def _is_blank(r, base):
    head = r.read(base, 4096)
    return len(head) > 0 and head.count(0) == len(head)


def identify(r, base=0, size=None, depth=0, partitions=True):
    """Identify what lives at `base`.  Returns a nested dict."""
    result = {"offset": base, "size": size, "matches": [], "partition_table": None}
    if r.size and base >= r.size:
        result["error"] = "offset is beyond the end of the device/image"
        return result
    matches = []
    for p in FS_PROBES:
        matches.extend(_run_probe(p, r, base))
    strong = [m for m in matches if not m["weak"]]
    if strong:
        matches = strong
    has_fs = any(m["kind"] in ("filesystem", "crypto", "container", "raid") for m in matches)
    result["matches"] = matches

    table = None
    if partitions and depth < MAX_DEPTH:
        try:
            if depth == 0:
                table = probe_gpt(r, base, size or r.size)
                if table is None:
                    table = probe_apm(r, base, size or r.size)
                if table is None and not has_fs:
                    table = probe_mbr(r, base, size or r.size)
            if table is None and depth <= 1:
                table = probe_disklabel(r, base, size or r.size)
        except (struct.error, IndexError, ValueError, UnicodeError):
            table = None
    if table:
        if table["scheme"] == "gpt" and depth == 0:
            try:
                mbr = probe_mbr(r, base, size or r.size)
            except (struct.error, IndexError, ValueError):
                mbr = None
            if mbr and not mbr["protective"]:
                table["hybrid_mbr"] = True
        for part in table["partitions"]:
            if part.get("skip_content"):
                part.pop("skip_content")
                continue
            part.pop("skip_content", None)
            off = part["offset"]
            if table["scheme"] == "bsd" and base and depth:
                # FreeBSD labels are slice-relative; NetBSD labels absolute.
                rel = part.pop("relative_offset")
                abs_ok = any(_run_probe(p, r, off) for p in FS_PROBES) if off else False
                if not abs_ok and rel != off and any(_run_probe(p, r, rel) for p in FS_PROBES):
                    off = part["offset"] = rel
            else:
                part.pop("relative_offset", None)
            if r.size and off >= r.size:
                part["content"] = {"offset": off, "size": part["size"], "matches": [],
                                   "partition_table": None, "error": "partition starts beyond end of device/image"}
                continue
            part["content"] = identify(r, off, part["size"], depth + 1, partitions)
            if not part["content"]["matches"] and not part["content"]["partition_table"]:
                part["content"]["blank"] = _is_blank(r, off)
    result["partition_table"] = table
    if depth == 0 and not matches and not table:
        result["blank"] = _is_blank(r, base)
    return result


def identify_path(path, offset=0, partitions=True):
    with Reader(path) as r:
        res = identify(r, offset, (r.size - offset) if r.size else None, 0, partitions)
        res["path"] = path
        res["device_size"] = r.size or None
        return res


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

_SIZE_KEYS = {"size", "used", "allocated", "data_offset", "data_size", "virtual_size",
              "header_size", "mft_offset", "embedded_offset", "label_offset", "superblock_offset"}


def _fmt_value(k, v):
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, int) and k in _SIZE_KEYS:
        return "%s (%d bytes)" % (human(v), v) if v >= 1024 else str(v)
    if isinstance(v, int) and k.endswith("_size"):
        return str(v)
    return str(v)


def _print_match(m, indent, out):
    pad = " " * indent
    head = m["description"]
    if m.get("version") and m["kind"] not in ("image", "archive"):
        head += ", version " + str(m["version"])
    out.append(pad + head)
    rows = []
    if m.get("label"):
        rows.append(("label", m["label"]))
    if m.get("uuid"):
        rows.append(("uuid", m["uuid"]))
    nested = []
    for k, v in m["details"].items():
        if isinstance(v, list) and v and isinstance(v[0], dict):
            nested.append((k, v))
        else:
            rows.append((k.replace("_", " "), _fmt_value(k, v)))
    width = max((len(k) for k, _ in rows), default=0)
    for k, v in rows:
        out.append("%s  %-*s  %s" % (pad, width, k + ":", v))
    for k, items in nested:
        for i, item in enumerate(items):
            name = item.get("name")
            out.append('%s  %s %d: "%s"' % (pad, k.rstrip("s"), i + 1, name) if name is not None
                       else "%s  %s %d:" % (pad, k.rstrip("s"), i + 1))
            w = max(len(x) for x in item if x != "name")
            for ik, iv in item.items():
                if ik == "name" or iv is None:
                    continue
                out.append("%s      %-*s  %s" % (pad, w + 1, ik.replace("_", " ") + ":", _fmt_value(ik, iv)))


def _print_result(res, indent, out):
    pad = " " * indent
    if res.get("error"):
        out.append(pad + "error: " + res["error"])
        return
    for m in res["matches"]:
        _print_match(m, indent, out)
    table = res.get("partition_table")
    if table:
        head = table["description"]
        if table.get("hybrid_mbr"):
            head += " (with hybrid MBR)"
        out.append(pad + head)
        rows = [(k, v) for k, v in table.items()
                if k not in ("scheme", "description", "partitions", "hybrid_mbr", "protective", "usable_range")
                and v not in (None, "")]
        width = max((len(k) for k, _ in rows), default=0)
        for k, v in rows:
            out.append("%s  %-*s  %s" % (pad, width + 1, k.replace("_", " ") + ":", v))
        for p in table["partitions"]:
            desc = "%spartition %s" % (pad, p["index"])
            if p.get("logical"):
                desc += " (logical)"
            desc += ": %s" % p["type"]
            if p.get("type_id") is not None:
                desc += " [%s]" % p["type_id"]
            if p.get("name"):
                desc += ' "%s"' % p["name"]
            desc += "  @ %s, %s" % (human(p["offset"]), human(p["size"]))
            if p.get("bootable"):
                desc += ", bootable"
            if p.get("attributes"):
                desc += ", " + p["attributes"]
            out.append(desc)
            if p.get("uuid"):
                out.append("%s  uuid: %s" % (pad, p["uuid"]))
            c = p.get("content")
            if c is None:
                continue
            if not c["matches"] and not c["partition_table"] and not c.get("error"):
                out.append(pad + "    " + ("(empty: all zeros)" if c.get("blank") else "unknown: no recognised signature"))
            else:
                _print_result(c, indent + 4, out)
    if indent == 0 and not res["matches"] and not table and not res.get("error"):
        out.append(pad + ("empty: the first 4 KiB are all zeros" if res.get("blank")
                          else "unknown: no recognised filesystem or partition-table signature"))


def format_text(res):
    out = []
    head = res["path"]
    if res.get("device_size"):
        head += "  (%s, %d bytes)" % (human(res["device_size"]), res["device_size"])
    if res["offset"]:
        head += "  probing at offset %d" % res["offset"]
    out.append(head)
    _print_result(res, 2, out)
    return "\n".join(out)


def _parse_size(s):
    s = s.strip().lower()
    mult = 1
    for suf, m in (("tib", 1 << 40), ("gib", 1 << 30), ("mib", 1 << 20), ("kib", 1 << 10),
                   ("t", 1 << 40), ("g", 1 << 30), ("m", 1 << 20), ("k", 1 << 10), ("s", 512)):
        if s.endswith(suf):
            mult = m
            s = s[:-len(suf)]
            break
    return int(s, 0) * mult


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="wail",
        description="What Am I Looking at: identify the filesystem (or partition table, "
                    "RAID/LVM/crypto container, or disk-image format) on a device or image file. "
                    "Strictly read-only.")
    ap.add_argument("target", nargs="+", help="block device (/dev/disk4, /dev/sdb1, \\\\.\\PhysicalDrive1) or image file")
    ap.add_argument("-j", "--json", action="store_true", help="machine-readable JSON output")
    ap.add_argument("-o", "--offset", default="0",
                    help="probe at this byte offset (suffixes K/M/G/T, or s for 512-byte sectors)")
    ap.add_argument("-P", "--no-partitions", action="store_true",
                    help="do not descend into partition tables")
    ap.add_argument("-V", "--version", action="version", version="wail " + __version__)
    args = ap.parse_args(argv)
    try:
        offset = _parse_size(args.offset)
    except ValueError:
        ap.error("bad offset: %r" % args.offset)

    results = []
    status = 0
    for target in args.target:
        try:
            res = identify_path(target, offset, not args.no_partitions)
        except OSError as e:
            msg = "%s: %s" % (target, e.strerror or e)
            if getattr(e, "errno", None) in (1, 13):
                msg += " (raw devices need root: try sudo; on macOS the terminal may also need Full Disk Access)"
            if args.json:
                results.append({"path": target, "error": msg})
            else:
                print(msg, file=sys.stderr)
            status = 2
            continue
        results.append(res)
        if not res["matches"] and not res["partition_table"]:
            status = max(status, 1)
        if not args.json:
            print(format_text(res))
            if len(args.target) > 1:
                print()
    if args.json:
        print(json.dumps(results if len(results) != 1 else results[0], indent=2))
    return status


if __name__ == "__main__":
    sys.exit(main())
