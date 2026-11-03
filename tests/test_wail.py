"""Tests for wail.

Synthetic fixtures place the real on-disk magic numbers and the fields the
probes read at their documented offsets; they are not mountable filesystems.
Real-image tests (macOS only, need hdiutil) are run when WAIL_REAL_TESTS=1;
attaching a disk image as a block device is run when WAIL_DEVICE_TESTS=1.
"""
import hashlib
import io
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import wail  # noqa: E402

KiB, MiB = 1024, 1024 * 1024


def build(size, writes):
    """Return a zero-filled bytearray with (offset, bytes) patches applied."""
    img = bytearray(size)
    for off, data in writes:
        img[off:off + len(data)] = data
    return img


def pad(b, n, fill=b"\0"):
    return bytes(b) + fill * (n - len(b))


class ImageCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="wail-test-")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def write_image(self, name, data):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as f:
            f.write(data)
        return path

    def ident(self, name, data, **kw):
        path = self.write_image(name, data)
        return wail.identify_path(path, **kw)

    def first(self, res):
        self.assertTrue(res["matches"], "no match: %r" % res)
        return res["matches"][0]

    def assertFS(self, res, fstype, label=None, **details):
        m = self.first(res)
        self.assertEqual(m["type"], fstype, m)
        if label is not None:
            self.assertEqual(m["label"], label, m)
        for k, v in details.items():
            self.assertEqual(m["details"].get(k), v, m)
        return m


# --------------------------------------------------------------------------
# Fixture builders (byte offsets follow the on-disk formats)
# --------------------------------------------------------------------------

def ext_sb(label=b"rootfs", compat=0x4, incompat=0x242, rocompat=0x7B):
    sb = bytearray(1024)
    struct.pack_into("<I", sb, 0, 1000)          # inodes count
    struct.pack_into("<I", sb, 4, 16384)         # blocks count
    struct.pack_into("<I", sb, 0x18, 2)          # log block size -> 4096
    struct.pack_into("<I", sb, 0x20, 8192)       # blocks per group
    struct.pack_into("<H", sb, 0x38, 0xEF53)     # magic
    struct.pack_into("<H", sb, 0x3A, 1)          # state: clean
    struct.pack_into("<I", sb, 0x4C, 1)          # rev level
    struct.pack_into("<I", sb, 0x5C, compat)
    struct.pack_into("<I", sb, 0x60, incompat)
    struct.pack_into("<I", sb, 0x64, rocompat)
    sb[0x68:0x78] = uuid.UUID("12345678-1234-5678-1234-567812345678").bytes
    sb[0x78:0x88] = pad(label, 16)
    sb[0x88:0x8A] = b"/\0"
    return bytes(sb)


def ntfs_image(size=2 * MiB, label="NTFSVOL"):
    bps, spc, mft_lcn = 512, 8, 4
    boot = bytearray(512)
    boot[0:3] = b"\xEB\x52\x90"
    boot[3:11] = b"NTFS    "
    struct.pack_into("<H", boot, 11, bps)
    boot[13] = spc
    boot[21] = 0xF8
    struct.pack_into("<Q", boot, 40, size // bps - 1)
    struct.pack_into("<Q", boot, 48, mft_lcn)
    struct.pack_into("<Q", boot, 56, mft_lcn + 100)
    struct.pack_into("<b", boot, 64, -10)        # 1024-byte MFT records
    struct.pack_into("<Q", boot, 72, 0x1234567890ABCDEF)
    boot[510:512] = b"\x55\xAA"
    # MFT record 3 ($Volume) with $VOLUME_NAME and $VOLUME_INFORMATION.
    rec = bytearray(1024)
    rec[0:4] = b"FILE"
    struct.pack_into("<HH", rec, 4, 48, 3)       # usa offset / count
    struct.pack_into("<H", rec, 20, 56)          # first attribute
    name = label.encode("utf-16-le")
    attr = bytearray(24 + len(name))
    struct.pack_into("<II", attr, 0, 0x60, (len(attr) + 7) & ~7)
    struct.pack_into("<I", attr, 16, len(name))
    struct.pack_into("<H", attr, 20, 24)
    attr[24:] = name
    attr = pad(attr, (len(attr) + 7) & ~7)
    info = bytearray(24 + 12)
    struct.pack_into("<II", info, 0, 0x70, 40)
    struct.pack_into("<I", info, 16, 12)
    struct.pack_into("<H", info, 20, 24)
    info[24 + 8] = 3
    info[24 + 9] = 1
    info = pad(info, 40)
    body = attr + info + b"\xFF\xFF\xFF\xFF"
    rec[56:56 + len(body)] = body
    usn = b"\x07\x00"
    rec[48:50] = usn
    rec[50:52] = rec[510:512]
    rec[52:54] = rec[1022:1024]
    rec[510:512] = usn
    rec[1022:1024] = usn
    mft = mft_lcn * spc * bps
    return build(size, [(0, bytes(boot)), (mft + 3 * 1024, bytes(rec))])


def fat12_image():
    boot = bytearray(512)
    boot[0:3] = b"\xEB\x3C\x90"
    boot[3:11] = b"MSWIN4.1"
    struct.pack_into("<HBHBHHBHHHII", boot, 11, 512, 1, 1, 2, 224, 2880, 0xF0, 9, 18, 2, 0, 0)
    boot[38] = 0x29
    struct.pack_into("<I", boot, 39, 0xDEADBEEF)
    boot[43:54] = b"BOOTLABEL  "
    boot[54:62] = b"FAT12   "
    boot[510:512] = b"\x55\xAA"
    entry = bytearray(32)
    entry[0:11] = b"ROOTLABEL  "
    entry[11] = 0x08
    root = (1 + 2 * 9) * 512
    return build(1440 * KiB, [(0, bytes(boot)), (root, bytes(entry))])


def exfat_image():
    size = 4 * MiB
    boot = bytearray(512)
    boot[0:3] = b"\xEB\x76\x90"
    boot[3:11] = b"EXFAT   "
    struct.pack_into("<Q", boot, 72, size // 512)
    struct.pack_into("<IIIII", boot, 80, 24, 100, 128, 1000, 5)   # fat off/len, heap off, clusters, root
    struct.pack_into("<I", boot, 100, 0x1A2B3C4D)
    struct.pack_into("<H", boot, 104, 0x0100)
    boot[108], boot[109] = 9, 3
    boot[510:512] = b"\x55\xAA"
    root = (128 + (5 - 2) * 8) * 512
    lbl = bytearray(32)
    lbl[0] = 0x83
    lbl[1] = 8
    lbl[2:18] = "EXFATSYN".encode("utf-16-le")
    guid = bytearray(32)
    guid[0] = 0xA0
    guid[16:32] = uuid.UUID("11111111-2222-3333-4444-555555555555").bytes_le
    return build(size, [(0, bytes(boot)), (root, bytes(lbl) + bytes(guid))])


def hfsplus_blocks(label="HFSVOL", sig=b"H+", version=4, attrs=0x2100, cat_block=10):
    """Return (volume-header, catalog-bytes) for an HFS+ volume at offset 0."""
    vh = bytearray(512)
    vh[0:2] = sig
    struct.pack_into(">HI", vh, 2, version, attrs)
    vh[8:12] = b"HFSJ"
    struct.pack_into(">I", vh, 16, 3000000000)
    struct.pack_into(">II", vh, 32, 7, 3)                  # files, folders
    struct.pack_into(">II", vh, 40, 4096, 2048)            # block size, total blocks
    struct.pack_into(">I", vh, 272 + 16, cat_block)        # catalog extent 0 start
    vh[104:112] = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    hdr = bytearray(4096)
    hdr[8] = 1                                             # header node
    struct.pack_into(">I", hdr, 24, 1)                     # first leaf node
    struct.pack_into(">H", hdr, 32, 4096)                  # node size
    hdr[51] = 0xBC if sig == b"HX" else 0xCF
    leaf = bytearray(4096)
    leaf[8] = 0xFF                                         # leaf node
    name = label.encode("utf-16-be")
    struct.pack_into(">HIH", leaf, 14, 6 + len(name), 1, len(label))   # name length in UTF-16 units
    leaf[22:22 + len(name)] = name
    struct.pack_into(">H", leaf, 4094, 14)
    return bytes(vh), bytes(hdr) + bytes(leaf)


def zfs_nvlist(pairs):
    def xdr_pair(name, typ, val):
        n = name.encode()
        body = struct.pack(">i", len(n)) + pad(n, (len(n) + 3) & ~3) + struct.pack(">ii", typ, 1)
        if typ == 9:
            v = val.encode()
            body += struct.pack(">i", len(v)) + pad(v, (len(v) + 3) & ~3)
        else:
            body += struct.pack(">Q", val)
        return struct.pack(">ii", len(body) + 8, 64) + body
    out = b"\x01\x00\x00\x00" + struct.pack(">ii", 0, 1)
    for p in pairs:
        out += xdr_pair(*p)
    return out + b"\0" * 8


def zfs_image():
    nv = zfs_nvlist([("version", 8, 5000), ("name", 9, "tank"), ("state", 8, 1),
                     ("pool_guid", 8, 0x1122334455667788), ("guid", 8, 0xAABBCCDDEEFF0011),
                     ("txg", 8, 42), ("hostname", 9, "nas"), ("vdev_children", 8, 1)])
    ub = struct.pack("<QQQQQ", 0x00BAB10C, 5000, 42, 7, 1700000000)
    ub_old = struct.pack("<QQQQQ", 0x00BAB10C, 5000, 41, 7, 1600000000)
    return build(1 * MiB, [(0x4000, nv), (0x20000, ub_old), (0x20400, ub)])


def gpt_image():
    size = 8 * MiB
    mbr = bytearray(512)
    mbr[446 + 4] = 0xEE
    struct.pack_into("<II", mbr, 446 + 8, 1, size // 512 - 1)
    mbr[510:512] = b"\x55\xAA"
    hdr = bytearray(512)
    hdr[0:8] = b"EFI PART"
    struct.pack_into("<IIII", hdr, 8, 0x00010000, 92, 0, 0)
    struct.pack_into("<QQQQ", hdr, 24, 1, size // 512 - 1, 34, size // 512 - 34)
    hdr[56:72] = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").bytes_le
    struct.pack_into("<QII", hdr, 72, 2, 128, 128)

    def entry(tguid, first, last, name):
        e = bytearray(128)
        e[0:16] = uuid.UUID(tguid).bytes_le
        e[16:32] = uuid.uuid4().bytes_le
        struct.pack_into("<QQQ", e, 32, first, last, 0)
        e[56:56 + 2 * len(name)] = name.encode("utf-16-le")
        return bytes(e)
    entries = entry("0FC63DAF-8483-4772-8E79-3D69D8477DE4", 2048, 2048 + 4095, "rootfs") + \
        entry("0657FD6D-A4AB-43C4-84E5-0933C84B4F4F", 8192, 8192 + 2047, "swap")
    swap = bytearray(4096)
    swap[4086:4096] = b"SWAPSPACE2"
    hdrs = bytearray(64)
    struct.pack_into("<III", hdrs, 0, 1, 1023, 0)
    hdrs[12:28] = uuid.UUID("99999999-9999-9999-9999-999999999999").bytes
    hdrs[28:44] = pad(b"swaplabel", 16)
    return build(size, [(0, bytes(mbr)), (512, bytes(hdr)), (1024, entries),
                        (2048 * 512 + 1024, ext_sb(b"gptroot")),
                        (8192 * 512, bytes(swap)), (8192 * 512 + 1024, bytes(hdrs))])


def mbr_image():
    size = 8 * MiB
    mbr = bytearray(512)

    def ent(off, status, ptype, lba, count):
        mbr[off] = status
        mbr[off + 4] = ptype
        struct.pack_into("<II", mbr, off + 8, lba, count)
    ent(446, 0x80, 0x83, 2048, 2048)       # primary: ext2 at 1 MiB
    ent(462, 0x00, 0x05, 4096, 8192)       # extended container at 2 MiB
    mbr[510:512] = b"\x55\xAA"
    ebr1 = bytearray(512)
    ebr1[446 + 4] = 0x82
    struct.pack_into("<II", ebr1, 446 + 8, 2048, 2048)      # logical 5 at 2 MiB + 1 MiB
    ebr1[462 + 4] = 0x05
    struct.pack_into("<II", ebr1, 462 + 8, 4096, 4096)      # next EBR at 2 MiB + 2 MiB
    ebr1[510:512] = b"\x55\xAA"
    ebr2 = bytearray(512)
    ebr2[446 + 4] = 0x07
    struct.pack_into("<II", ebr2, 446 + 8, 2048, 2048)      # logical 6 at 4 MiB + 1 MiB
    ebr2[510:512] = b"\x55\xAA"
    swap = bytearray(4096)
    swap[4086:4096] = b"SWAPSPACE2"
    ntfs = ntfs_image(1 * MiB, "LOGICAL6")
    return build(size, [(0, bytes(mbr)), (1 * MiB + 1024, ext_sb(b"primary1", compat=0, incompat=2, rocompat=3)),
                        (2 * MiB, bytes(ebr1)), (3 * MiB, bytes(swap)), (4 * MiB, bytes(ebr2)),
                        (5 * MiB, bytes(ntfs))])


def ufs_sb(version=2, label=b"ufsvol", order="<"):
    sb = bytearray(0x560)
    struct.pack_into(order + "II", sb, 48, 32768, 4096)
    sb[212:216] = b"/mnt"
    sb[680:680 + len(label)] = label
    struct.pack_into(order + "I", sb, 0x55C, 0x19540119 if version == 2 else 0x00011954)
    return bytes(sb)


def disklabel(parts, secsize=512):
    lbl = bytearray(512)
    struct.pack_into("<I", lbl, 0, 0x82564557)
    lbl[8:16] = b"SCSI\0\0\0\0"
    lbl[24:32] = b"testpack"
    struct.pack_into("<I", lbl, 40, secsize)
    struct.pack_into("<I", lbl, 132, 0x82564557)
    struct.pack_into("<H", lbl, 138, len(parts))
    for i, (psize, poff, fstype) in enumerate(parts):
        struct.pack_into("<IIIBBH", lbl, 148 + 16 * i, psize, poff, 0, fstype, 0, 0)
    return bytes(lbl)


# --------------------------------------------------------------------------
# Tests: Linux filesystems
# --------------------------------------------------------------------------

class LinuxFilesystems(ImageCase):
    def test_ext4(self):
        res = self.ident("ext4.img", build(4 * MiB, [(1024, ext_sb(b"rootfs"))]))
        m = self.assertFS(res, "ext4", "rootfs", block_size=4096, last_mounted_on="/")
        self.assertEqual(m["uuid"], "12345678-1234-5678-1234-567812345678")
        self.assertIn("clean", m["details"]["state"])

    def test_ext3(self):
        res = self.ident("ext3.img", build(4 * MiB, [(1024, ext_sb(b"e3", compat=4, incompat=2, rocompat=3))]))
        self.assertFS(res, "ext3", "e3")

    def test_ext2(self):
        res = self.ident("ext2.img", build(4 * MiB, [(1024, ext_sb(b"e2", compat=0, incompat=2, rocompat=3))]))
        self.assertFS(res, "ext2", "e2")

    def test_ext_needs_recovery(self):
        res = self.ident("ext4r.img", build(4 * MiB, [(1024, ext_sb(b"r", incompat=0x246))]))
        self.assertIn("journal needs recovery", self.first(res)["details"]["state"])

    def test_xfs(self):
        sb = bytearray(512)
        sb[0:4] = b"XFSB"
        struct.pack_into(">IQ", sb, 4, 4096, 262144)
        sb[32:48] = uuid.UUID("abcdefab-cdef-abcd-efab-cdefabcdefab").bytes
        struct.pack_into(">HHH", sb, 100, 0x8005, 512, 512)
        sb[108:120] = pad(b"xfsvol", 12)
        res = self.ident("xfs.img", build(1 * MiB, [(0, bytes(sb))]))
        m = self.assertFS(res, "xfs", "xfsvol", block_size=4096, size=1 << 30)
        self.assertTrue(m["version"].startswith("v5"))

    def test_btrfs(self):
        sb = bytearray(4096)
        sb[0x20:0x30] = uuid.UUID("deadbeef-dead-beef-dead-beefdeadbeef").bytes
        sb[0x40:0x48] = b"_BHRfS_M"
        struct.pack_into("<QQ", sb, 0x70, 10 * MiB, 1 * MiB)
        struct.pack_into("<Q", sb, 0x88, 1)
        struct.pack_into("<II", sb, 0x90, 4096, 16384)
        sb[0x12B:0x12B + 8] = b"btrfsvol"
        res = self.ident("btrfs.img", build(128 * KiB, [(0x10000, bytes(sb))]))
        m = self.assertFS(res, "btrfs", "btrfsvol", size=10 * MiB, node_size=16384)
        self.assertEqual(m["uuid"], "deadbeef-dead-beef-dead-beefdeadbeef")

    def test_f2fs(self):
        sb = bytearray(2048)
        struct.pack_into("<IHH", sb, 0, 0xF2F52010, 1, 15)
        struct.pack_into("<I", sb, 16, 12)
        struct.pack_into("<Q", sb, 36, 4096)
        sb[108:124] = uuid.UUID("f2f5f2f5-f2f5-f2f5-f2f5-f2f5f2f5f2f5").bytes
        sb[124:124 + 8] = "f2vol".encode("utf-16-le")
        res = self.ident("f2fs.img", build(64 * KiB, [(1024, bytes(sb))]))
        self.assertFS(res, "f2fs", "f2vol", block_size=4096, size=16 * MiB)

    def test_jfs(self):
        sb = bytearray(512)
        sb[0:4] = b"JFS1"
        struct.pack_into("<IQIHHIH", sb, 4, 2, 2048, 4096, 12, 3, 512, 9)
        sb[136:152] = uuid.UUID("0f0f0f0f-0f0f-0f0f-0f0f-0f0f0f0f0f0f").bytes
        sb[152:158] = b"jfsvol"
        res = self.ident("jfs.img", build(64 * KiB, [(0x8000, bytes(sb))]))
        self.assertFS(res, "jfs", "jfsvol", block_size=4096)

    def test_reiserfs(self):
        sb = bytearray(512)
        struct.pack_into("<I", sb, 0, 65536)
        struct.pack_into("<H", sb, 44, 4096)
        sb[52:61] = b"ReIsEr2Fs"
        sb[0x54:0x64] = uuid.UUID("5e15e75e-15e7-5e15-e75e-15e75e15e75e").bytes
        sb[0x64:0x6A] = b"reiser"
        res = self.ident("reiserfs.img", build(128 * KiB, [(0x10000, bytes(sb))]))
        m = self.assertFS(res, "reiserfs", "reiser", block_size=4096)
        self.assertEqual(m["version"], "3.6")

    def test_reiser4(self):
        sb = bytearray(512)
        sb[0:7] = b"ReIsEr4"
        struct.pack_into("<H", sb, 18, 4096)
        sb[36:42] = b"four00"
        res = self.ident("reiser4.img", build(128 * KiB, [(0x10000, bytes(sb))]))
        self.assertFS(res, "reiser4", "four00", block_size=4096)

    def test_nilfs2(self):
        sb = bytearray(1024)
        struct.pack_into("<IHH", sb, 0, 2, 0, 0x3434)
        struct.pack_into("<I", sb, 20, 2)
        struct.pack_into("<Q", sb, 32, 64 * MiB)
        sb[168:174] = b"nilvol"
        res = self.ident("nilfs2.img", build(64 * KiB, [(1024, bytes(sb))]))
        self.assertFS(res, "nilfs2", "nilvol", block_size=4096, size=64 * MiB)

    def test_bcachefs(self):
        sb = bytearray(512)
        struct.pack_into("<H", sb, 16, 31)
        sb[24:40] = wail._BCACHEFS_MAGIC
        sb[56:72] = uuid.UUID("bcbcbcbc-bcbc-bcbc-bcbc-bcbcbcbcbcbc").bytes
        sb[72:78] = b"bcache"
        res = self.ident("bcachefs.img", build(64 * KiB, [(4096, bytes(sb))]))
        m = self.assertFS(res, "bcachefs", "bcache")
        self.assertEqual(m["uuid"], "bcbcbcbc-bcbc-bcbc-bcbc-bcbcbcbcbcbc")

    def test_erofs(self):
        sb = bytearray(128)
        struct.pack_into("<I", sb, 0, 0xE0F5E1E2)
        sb[12] = 12
        struct.pack_into("<I", sb, 36, 256)
        sb[64:69] = b"erofs"
        res = self.ident("erofs.img", build(64 * KiB, [(1024, bytes(sb))]))
        self.assertFS(res, "erofs", "erofs", block_size=4096, size=1 * MiB)

    def test_ocfs2(self):
        sb = bytearray(512)
        sb[0:6] = b"OCFSV2"
        struct.pack_into("<HH", sb, 0xC0, 1, 0)
        struct.pack_into("<II", sb, 0xC0 + 56, 12, 20)
        sb[0xC0 + 80:0xC0 + 87] = b"cluster"
        res = self.ident("ocfs2.img", build(64 * KiB, [(0x2000, bytes(sb))]))
        self.assertFS(res, "ocfs2", "cluster", block_size=4096, cluster_size=1 << 20)

    def test_gfs2(self):
        sb = bytearray(512)
        struct.pack_into(">I", sb, 0, 0x01161970)
        struct.pack_into(">I", sb, 24, 1801)
        struct.pack_into(">I", sb, 36, 4096)
        sb[92:100] = b"lock_dlm"
        sb[156:166] = b"cluster:fs"
        res = self.ident("gfs2.img", build(128 * KiB, [(0x10000, bytes(sb))]))
        self.assertFS(res, "gfs2", "cluster:fs", lock_protocol="lock_dlm")

    def test_squashfs(self):
        sb = bytearray(96)
        sb[0:4] = b"hsqs"
        struct.pack_into("<I", sb, 12, 131072)
        struct.pack_into("<H", sb, 20, 4)
        struct.pack_into("<HH", sb, 28, 4, 0)
        struct.pack_into("<Q", sb, 40, 12345)
        res = self.ident("squashfs.img", build(8 * KiB, [(0, bytes(sb))]))
        m = self.assertFS(res, "squashfs", compression="xz", size=12345)
        self.assertEqual(m["version"], "4.0")

    def test_cramfs(self):
        sb = bytearray(64)
        struct.pack_into("<II", sb, 0, 0x28CD3D45, 8192)
        sb[48:64] = b"Compressed ROMFS"
        res = self.ident("cramfs.img", build(8 * KiB, [(0, bytes(sb))]))
        self.assertFS(res, "cramfs", "Compressed ROMFS", size=8192)

    def test_romfs(self):
        res = self.ident("romfs.img", build(8 * KiB, [(0, b"-rom1fs-" + struct.pack(">II", 4096, 0) + b"romvol")]))
        self.assertFS(res, "romfs", "romvol")

    def test_minix(self):
        sb = bytearray(64)
        struct.pack_into("<HHH", sb, 4, 1, 1, 0)
        struct.pack_into("<H", sb, 16, 0x2478)
        res = self.ident("minix.img", build(8 * KiB, [(1024, bytes(sb))]))
        m = self.assertFS(res, "minix")
        self.assertEqual(m["version"], "2")

    def test_ubifs_jffs2(self):
        res = self.ident("ubifs.img", build(8 * KiB, [(0, struct.pack("<IIB", 0x06101831, 0, 6))]))
        self.assertFS(res, "ubifs")
        res = self.ident("jffs2.img", build(8 * KiB, [(0, struct.pack("<HH", 0x1985, 0xE001))]))
        self.assertFS(res, "jffs2")

    def test_swap(self):
        img = build(8 * KiB, [(4086, b"SWAPSPACE2")])
        struct.pack_into("<II", img, 1024, 1, 1023)
        img[1036:1052] = uuid.UUID("77777777-7777-7777-7777-777777777777").bytes
        img[1052:1058] = b"swap01"
        m = self.assertFS(self.ident("swap.img", img), "swap", "swap01", page_size=4096, size=4 * MiB)
        self.assertEqual(m["uuid"], "77777777-7777-7777-7777-777777777777")


class ContainersAndCrypto(ImageCase):
    def test_luks1(self):
        hdr = bytearray(512)
        hdr[0:8] = b"LUKS\xba\xbe\x00\x01"
        hdr[8:11] = b"aes"
        hdr[40:51] = b"xts-plain64"
        hdr[72:78] = b"sha256"
        hdr[168:204] = b"12345678-aaaa-bbbb-cccc-123456789abc"
        m = self.assertFS(self.ident("luks1.img", build(8 * KiB, [(0, bytes(hdr))])), "luks",
                          cipher="aes-xts-plain64", hash="sha256")
        self.assertEqual(m["version"], "1")
        self.assertEqual(m["kind"], "crypto")

    def test_luks2(self):
        hdr = bytearray(512)
        hdr[0:8] = b"LUKS\xba\xbe\x00\x02"
        struct.pack_into(">Q", hdr, 8, 16384)
        hdr[24:30] = b"secret"
        hdr[72:78] = b"sha256"
        hdr[168:204] = b"abcdefab-1111-2222-3333-abcdefabcdef"
        m = self.assertFS(self.ident("luks2.img", build(8 * KiB, [(0, bytes(hdr))])), "luks", "secret", header_size=16384)
        self.assertEqual(m["uuid"], "abcdefab-1111-2222-3333-abcdefabcdef")

    def test_bitlocker(self):
        sb = bytearray(512)
        sb[3:11] = b"-FVE-FS-"
        sb[160:176] = uuid.UUID("4967d63b-2e29-4ad8-8399-f6a339e3d001").bytes_le
        m = self.assertFS(self.ident("bitlocker.img", build(8 * KiB, [(0, bytes(sb))])), "bitlocker")
        self.assertEqual(m["uuid"], "4967D63B-2E29-4AD8-8399-F6A339E3D001")

    def test_lvm2(self):
        lbl = bytearray(512)
        lbl[0:8] = b"LABELONE"
        struct.pack_into("<QII", lbl, 8, 1, 0, 32)
        lbl[24:32] = b"LVM2 001"
        lbl[32:64] = b"abcdefghijklmnopqrstuvwxyz012345"
        struct.pack_into("<Q", lbl, 64, 100 * MiB)
        m = self.assertFS(self.ident("lvm.img", build(8 * KiB, [(512, bytes(lbl))])), "lvm2", size=100 * MiB)
        self.assertEqual(m["uuid"], "abcdef-ghij-klmn-opqr-stuv-wxyz-012345")
        self.assertEqual(m["kind"], "container")

    def test_mdraid12(self):
        sb = bytearray(256)
        struct.pack_into("<II", sb, 0, 0xA92B4EFC, 1)
        sb[16:32] = uuid.UUID("0d0d0d0d-0d0d-0d0d-0d0d-0d0d0d0d0d0d").bytes
        sb[32:42] = b"host:array"
        struct.pack_into("<i", sb, 72, 5)
        struct.pack_into("<I", sb, 92, 3)
        struct.pack_into("<QQ", sb, 128, 2048, 100000)
        m = self.assertFS(self.ident("md.img", build(16 * KiB, [(4096, bytes(sb))])), "mdraid", "host:array",
                          level="raid5", raid_disks=3, data_offset=1 * MiB)
        self.assertEqual(m["version"], "1.2")

    def test_zfs(self):
        m = self.assertFS(self.ident("zfs.img", zfs_image()), "zfs", "tank", txg=42, pool_state="exported",
                          hostname="nas", byte_order="little-endian")
        self.assertEqual(m["uuid"], "1122334455667788")
        self.assertIn("5000", m["version"])

    def test_zfs_second_label_only(self):
        img = zfs_image()
        img2 = build(1 * MiB, [(0x40000, bytes(img[:0x40000]))])
        self.assertFS(self.ident("zfs2.img", img2), "zfs", "tank", label_offset=0x40000)


class WindowsFilesystems(ImageCase):
    def test_ntfs(self):
        m = self.assertFS(self.ident("ntfs.img", ntfs_image()), "ntfs", "NTFSVOL", cluster_size=4096,
                          size=2 * MiB, state="clean")
        self.assertEqual(m["version"], "3.1")
        self.assertEqual(m["uuid"], "1234567890ABCDEF")

    def test_ntfs_without_mft(self):
        img = ntfs_image()
        img[16384:16384 + 8192] = b"\0" * 8192
        m = self.assertFS(self.ident("ntfs-nomft.img", img), "ntfs")
        self.assertIsNone(m["label"])

    def test_fat12(self):
        m = self.assertFS(self.ident("fat12.img", fat12_image()), "fat12", "ROOTLABEL", clusters=2847)
        self.assertEqual(m["uuid"], "DEAD-BEEF")

    def test_fat16_and_32_by_cluster_count(self):
        img = fat12_image()
        struct.pack_into("<H", img, 19, 0)                # total sectors (16-bit) = 0 ...
        struct.pack_into("<I", img, 32, 40000)            # ... so the 32-bit field counts
        struct.pack_into("<H", img, 22, 60)
        self.assertFS(self.ident("fat16.img", img), "fat16", clusters=40000 - 1 - 120 - 14)
        img = fat12_image()
        struct.pack_into("<H", img, 19, 0)
        struct.pack_into("<I", img, 32, 200000)
        struct.pack_into("<H", img, 22, 0)                # 16-bit FAT size 0 ...
        struct.pack_into("<I", img, 36, 1000)             # ... 32-bit FAT size set
        struct.pack_into("<I", img, 44, 2)
        img[38] = 0
        img[66] = 0x29
        img[71:82] = b"BIGFAT     "
        img[82:90] = b"FAT32   "
        self.assertFS(self.ident("fat32.img", img), "fat32", "BIGFAT")

    def test_exfat(self):
        m = self.assertFS(self.ident("exfat.img", exfat_image()), "exfat", "EXFATSYN", cluster_size=4096,
                          volume_guid="11111111-2222-3333-4444-555555555555")
        self.assertEqual(m["uuid"], "1A2B-3C4D")
        self.assertEqual(m["version"], "1.0")

    def test_refs(self):
        sb = bytearray(512)
        sb[3:11] = b"ReFS\0\0\0\0"
        sb[16:20] = b"FSRS"
        struct.pack_into("<QII", sb, 24, 2048, 512, 8)
        sb[40], sb[41] = 3, 4
        m = self.assertFS(self.ident("refs.img", build(8 * KiB, [(0, bytes(sb))])), "refs", cluster_size=4096, size=1 * MiB)
        self.assertEqual(m["version"], "3.4")

    def test_hpfs(self):
        boot = bytearray(512)
        boot[38] = 0x29
        boot[43:54] = b"HPFSVOL    "
        sb = struct.pack("<IIB", 0xF995E849, 0xFA53E9C5, 2)
        self.assertFS(self.ident("hpfs.img", build(16 * KiB, [(0, bytes(boot)), (0x2000, sb)])), "hpfs", "HPFSVOL")


class AppleAndBSD(ImageCase):
    def test_hfsplus(self):
        vh, cat = hfsplus_blocks("HFSVOL")
        m = self.assertFS(self.ident("hfsplus.img", build(1 * MiB, [(1024, vh), (10 * 4096, cat)])),
                          "hfsplus", "HFSVOL", block_size=4096, files=7, folders=3)
        self.assertEqual(m["details"]["state"], "journaled, unmounted cleanly")
        self.assertEqual(m["uuid"], "0102030405060708")

    def test_hfsx(self):
        vh, cat = hfsplus_blocks("CaseSensitive", sig=b"HX", version=5)
        m = self.assertFS(self.ident("hfsx.img", build(1 * MiB, [(1024, vh), (10 * 4096, cat)])), "hfsx", "CaseSensitive")
        self.assertIn("case-sensitive", m["description"])

    def test_hfs_classic(self):
        mdb = bytearray(512)
        mdb[0:2] = b"BD"
        struct.pack_into(">I", mdb, 2, 3000000000)
        struct.pack_into(">HI", mdb, 18, 100, 4096)
        struct.pack_into(">H", mdb, 28, 16)
        mdb[36] = 6
        mdb[37:43] = b"OldMac"
        self.assertFS(self.ident("hfs.img", build(1 * MiB, [(1024, bytes(mdb))])), "hfs", "OldMac", block_size=4096, size=100 * 4096)

    def test_hfs_wrapper(self):
        mdb = bytearray(512)
        mdb[0:2] = b"BD"
        struct.pack_into(">HI", mdb, 18, 100, 4096)
        struct.pack_into(">H", mdb, 28, 16)          # drAlBlSt
        mdb[36] = 7
        mdb[37:44] = b"Wrapper"
        mdb[124:126] = b"H+"
        struct.pack_into(">HH", mdb, 126, 2, 90)     # embedded extent start block 2
        inner = 16 * 512 + 2 * 4096
        vh, cat = hfsplus_blocks("Inside", cat_block=10)
        img = build(1 * MiB, [(1024, bytes(mdb)), (inner + 1024, vh), (inner + 10 * 4096, cat)])
        m = self.assertFS(self.ident("hfswrap.img", img), "hfsplus", "Inside", wrapper_label="Wrapper", embedded_offset=inner)
        self.assertIn("wrapper", m["description"])

    def test_apfs_block0_only(self):
        sb = bytearray(4096)
        struct.pack_into("<I", sb, 24, 1)
        sb[32:36] = b"NXSB"
        struct.pack_into("<IQ", sb, 36, 4096, 25600)
        sb[72:88] = uuid.UUID("a9f5a9f5-a9f5-a9f5-a9f5-a9f5a9f5a9f5").bytes
        struct.pack_into("<I", sb, 180, 100)
        m = self.assertFS(self.ident("apfs.img", build(8 * KiB, [(0, bytes(sb))])), "apfs", size=100 * MiB,
                          checkpoint="block 0 copy only", volume_count=0)
        self.assertEqual(m["uuid"], "a9f5a9f5-a9f5-a9f5-a9f5-a9f5a9f5a9f5")

    def test_ufs2(self):
        m = self.assertFS(self.ident("ufs2.img", build(128 * KiB, [(65536, ufs_sb(2))])), "ufs", "ufsvol",
                          block_size=32768, fragment_size=4096, last_mounted_on="/mnt")
        self.assertEqual(m["version"], "2")

    def test_ufs1_bigendian(self):
        m = self.assertFS(self.ident("ufs1.img", build(16 * KiB, [(8192, ufs_sb(1, order=">"))])), "ufs",
                          byte_order="big-endian")
        self.assertEqual(m["version"], "1")

    def test_befs(self):
        sb = bytearray(64)
        sb[0:5] = b"haiku"
        struct.pack_into("<III", sb, 32, 0x42465331, 0, 2048)
        self.assertFS(self.ident("befs.img", build(8 * KiB, [(512, bytes(sb))])), "befs", "haiku", block_size=2048)

    def test_vmfs(self):
        self.assertFS(self.ident("vmfs.img", build(2 * MiB, [(0x100000, struct.pack("<II", 0xC001D00D, 5))])), "vmfs")


class Optical(ImageCase):
    def iso_bytes(self, udf=False):
        pvd = bytearray(2048)
        pvd[0] = 1
        pvd[1:6] = b"CD001"
        pvd[6] = 1
        pvd[8:40] = pad(b"SYNTHETIC", 32, b" ")
        pvd[40:72] = pad(b"ISOVOL", 32, b" ")
        struct.pack_into("<I", pvd, 80, 300)
        struct.pack_into("<H", pvd, 128, 2048)
        svd = bytearray(2048)
        svd[0] = 2
        svd[1:6] = b"CD001"
        svd[40:72] = pad("Joliet Vol".encode("utf-16-be"), 32)
        svd[88:91] = b"%/E"
        term = bytearray(2048)
        term[0] = 255
        term[1:6] = b"CD001"
        writes = [(0x8000, bytes(pvd)), (0x8800, bytes(svd)), (0x9000, bytes(term))]
        if udf:
            for i, ident in enumerate((b"BEA01", b"NSR02", b"TEA01")):
                d = bytearray(2048)
                d[1:6] = ident
                writes.append((0x9800 + i * 2048, bytes(d)))
            avdp = bytearray(512)
            struct.pack_into("<H", avdp, 0, 2)
            struct.pack_into("<II", avdp, 16, 2 * 2048, 300)
            writes.append((256 * 2048, bytes(avdp)))
            lvd = bytearray(512)
            struct.pack_into("<H", lvd, 0, 6)
            lvd[84] = 8
            lvd[85:92] = b"UDFTEST"
            lvd[211] = 8
            lvd[217:236] = b"*OSTA UDF Compliant"
            struct.pack_into("<H", lvd, 240, 0x0201)
            writes.append((300 * 2048, bytes(lvd)))
            pvdu = bytearray(512)
            struct.pack_into("<H", pvdu, 0, 1)
            pvdu[24] = 8
            pvdu[25:31] = b"UDFVID"
            pvdu[55] = 7
            writes.append((301 * 2048, bytes(pvdu)))
        return build(302 * 2048, writes)

    def test_iso9660_joliet(self):
        res = self.ident("iso.img", self.iso_bytes())
        m = self.assertFS(res, "iso9660", "ISOVOL", joliet_label="Joliet Vol", system_id="SYNTHETIC", size=300 * 2048)
        self.assertEqual(len(res["matches"]), 1)
        self.assertIsNone(res["partition_table"])

    def test_udf_bridge(self):
        res = self.ident("udf.img", self.iso_bytes(udf=True))
        types = [m["type"] for m in res["matches"]]
        self.assertEqual(types, ["iso9660", "udf"])
        udf = res["matches"][1]
        self.assertEqual(udf["label"], "UDFTEST")
        self.assertEqual(udf["version"], "2.01")
        self.assertEqual(udf["details"]["volume_id"], "UDFVID")


class PartitionTables(ImageCase):
    def test_gpt(self):
        res = self.ident("gpt.img", gpt_image())
        self.assertEqual(res["matches"], [])
        t = res["partition_table"]
        self.assertEqual(t["scheme"], "gpt")
        self.assertEqual(t["uuid"], "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")
        self.assertFalse(t.get("hybrid_mbr"))
        p1, p2 = t["partitions"]
        self.assertEqual((p1["name"], p1["type"], p1["offset"], p1["size"]), ("rootfs", "Linux filesystem", 1 * MiB, 2 * MiB))
        self.assertEqual(p1["content"]["matches"][0]["type"], "ext4")
        self.assertEqual(p1["content"]["matches"][0]["label"], "gptroot")
        self.assertEqual(p2["type"], "Linux swap")
        self.assertEqual(p2["content"]["matches"][0]["label"], "swaplabel")

    def test_gpt_backup_header(self):
        img = gpt_image()
        backup = bytes(img[512:1024])
        img[512:1024] = b"\0" * 512                        # wipe the primary header
        img[-512:] = backup
        res = self.ident("gpt-backup.img", img)
        self.assertIn("backup", res["partition_table"]["description"])
        self.assertEqual(len(res["partition_table"]["partitions"]), 2)

    def test_mbr_with_logicals(self):
        res = self.ident("mbr.img", mbr_image())
        t = res["partition_table"]
        self.assertEqual(t["scheme"], "mbr")
        parts = t["partitions"]
        self.assertEqual([p["index"] for p in parts], [1, 2, 5, 6])
        self.assertTrue(parts[0]["bootable"])
        self.assertEqual(parts[0]["content"]["matches"][0]["type"], "ext2")
        self.assertEqual(parts[2]["offset"], 3 * MiB)
        self.assertEqual(parts[2]["content"]["matches"][0]["type"], "swap")
        self.assertEqual(parts[3]["offset"], 5 * MiB)
        self.assertEqual(parts[3]["content"]["matches"][0]["label"], "LOGICAL6")
        self.assertEqual(parts[1]["content"]["matches"], [])

    def test_boot_sector_is_not_mistaken_for_mbr(self):
        res = self.ident("fatnotmbr.img", fat12_image())
        self.assertIsNone(res["partition_table"])
        res = self.ident("ntfsnotmbr.img", ntfs_image())
        self.assertIsNone(res["partition_table"])

    def test_apm(self):
        dd = bytearray(512)
        dd[0:2] = b"ER"
        struct.pack_into(">H", dd, 2, 512)
        pm1 = bytearray(512)
        pm1[0:2] = b"PM"
        struct.pack_into(">III", pm1, 4, 2, 1, 63)
        pm1[16:21] = b"Apple"
        pm1[48:67] = b"Apple_partition_map"
        pm2 = bytearray(512)
        pm2[0:2] = b"PM"
        struct.pack_into(">III", pm2, 4, 2, 64, 2048)
        pm2[16:19] = b"Mac"
        pm2[48:57] = b"Apple_HFS"
        vh, cat = hfsplus_blocks("APMHFS")
        img = build(2 * MiB, [(0, bytes(dd)), (512, bytes(pm1)), (1024, bytes(pm2)),
                              (32768 + 1024, vh), (32768 + 10 * 4096, cat)])
        t = self.ident("apm.img", img)["partition_table"]
        self.assertEqual(t["scheme"], "apm")
        self.assertNotIn("content", t["partitions"][0])
        self.assertEqual(t["partitions"][1]["content"]["matches"][0]["label"], "APMHFS")

    def test_bsd_disklabel_dedicated(self):
        lbl = disklabel([(4096, 2048, 7), (1024, 6144, 1), (16384, 0, 0)])
        img = build(4 * MiB, [(512, lbl), (1 * MiB + 65536, ufs_sb(2, b"bsdroot"))])
        t = self.ident("bsd.img", img)["partition_table"]
        self.assertEqual(t["scheme"], "bsd")
        self.assertEqual([p["index"] for p in t["partitions"]], ["a", "b"])
        self.assertEqual(t["partitions"][0]["type"], "4.2BSD FFS")
        self.assertEqual(t["partitions"][0]["content"]["matches"][0]["label"], "bsdroot")

    def test_bsd_disklabel_inside_mbr_slice_relative_offsets(self):
        slice_off = 1 * MiB
        mbr = bytearray(512)
        mbr[446 + 4] = 0xA5
        struct.pack_into("<II", mbr, 446 + 8, 2048, 6144)
        mbr[510:512] = b"\x55\xAA"
        lbl = disklabel([(4096, 16, 7)])                   # 'a' at 16 sectors into the slice
        img = build(4 * MiB, [(0, bytes(mbr)), (slice_off + 512, lbl),
                              (slice_off + 16 * 512 + 65536, ufs_sb(2, b"slice-a"))])
        t = self.ident("bsdslice.img", img)["partition_table"]
        self.assertEqual(t["partitions"][0]["type"], "FreeBSD")
        inner = t["partitions"][0]["content"]["partition_table"]
        self.assertEqual(inner["scheme"], "bsd")
        a = inner["partitions"][0]
        self.assertEqual(a["offset"], slice_off + 16 * 512)
        self.assertEqual(a["content"]["matches"][0]["label"], "slice-a")

    def test_no_partitions_flag(self):
        res = self.ident("gpt-np.img", gpt_image(), partitions=False)
        self.assertIsNone(res["partition_table"])

    def test_offset(self):
        res = self.ident("gpt-off.img", gpt_image(), offset=1 * MiB)
        self.assertEqual(res["matches"][0]["label"], "gptroot")


class ImageFormats(ImageCase):
    def test_qcow2(self):
        hdr = b"QFI\xfb" + struct.pack(">I", 3) + b"\0" * 16 + struct.pack(">Q", 10 * MiB)
        m = self.assertFS(self.ident("x.qcow2", build(8 * KiB, [(0, hdr)])), "qcow", virtual_size=10 * MiB)
        self.assertEqual(m["kind"], "image")

    def test_vmdk_vhdx_vdi_vhd(self):
        self.assertFS(self.ident("x.vmdk", build(8 * KiB, [(0, b"KDMV" + struct.pack("<IIQ", 1, 3, 20480))])), "vmdk", virtual_size=10 * MiB)
        self.assertFS(self.ident("x.vhdx", build(8 * KiB, [(0, b"vhdxfile")])), "vhdx")
        self.assertFS(self.ident("x.vdi", build(8 * KiB, [(0, b"<<< Oracle VM VirtualBox Disk Image >>>\n"), (0x40, struct.pack("<I", 0xBEDA107F))])), "vdi")
        footer = bytearray(512)
        footer[0:8] = b"conectix"
        struct.pack_into(">Q", footer, 40, 1440 * KiB)
        struct.pack_into(">I", footer, 60, 2)
        img = fat12_image() + bytes(footer)
        res = self.ident("fixed.vhd", img)
        self.assertEqual([m["type"] for m in res["matches"]], ["vhd", "fat12"])

    def test_dmg_trailer_and_gzip(self):
        img = build(8 * KiB, [(8 * KiB - 512, b"koly" + struct.pack(">I", 4))])
        self.assertFS(self.ident("x.dmg", img), "dmg")
        self.assertFS(self.ident("x.gz", build(8 * KiB, [(0, b"\x1f\x8b\x08")])), "gzip")
        self.assertFS(self.ident("x.E01", build(8 * KiB, [(0, b"EVF\x09\x0d\x0a\xff\x00")])), "ewf")


class Behaviour(ImageCase):
    def test_unknown_and_blank(self):
        res = self.ident("zeros.img", bytearray(64 * KiB))
        self.assertEqual(res["matches"], [])
        self.assertTrue(res["blank"])
        res = self.ident("junk.img", bytes(range(256)) * 256)
        self.assertEqual(res["matches"], [])
        self.assertFalse(res["blank"])

    def test_tiny_file_does_not_crash(self):
        res = self.ident("tiny.img", b"XFSB")
        self.assertEqual(res["matches"], [])

    def test_weak_matches_are_suppressed_by_strong_ones(self):
        img = build(1 * MiB, [(0, struct.pack("<HH", 0x1985, 0xE001)), (1024, ext_sb(b"strong"))])
        res = self.ident("weak.img", img)
        self.assertEqual([m["type"] for m in res["matches"]], ["ext4"])

    def test_strictly_read_only(self):
        path = self.write_image("ro.img", gpt_image())

        def digest():
            with open(path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        before = digest()
        st_before = os.stat(path)
        opened = []
        real_open = os.open

        def spy(p, flags, *a, **k):
            opened.append(flags)
            return real_open(p, flags, *a, **k)
        os.open = spy
        old = sys.stdout
        sys.stdout = io.StringIO()
        try:
            wail.identify_path(path)
            wail.main([path, "-j"])
        finally:
            os.open = real_open
            sys.stdout = old
        bad = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
        self.assertTrue(opened)
        for flags in opened:
            self.assertEqual(flags & bad, 0, "target opened with a writable flag")
        self.assertEqual(digest(), before)
        self.assertEqual(os.stat(path).st_mtime_ns, st_before.st_mtime_ns)

    def test_cli_json_and_exit_codes(self):
        path = self.write_image("cli.img", build(64 * KiB, [(1024, ext_sb(b"cli"))]))
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            rc = wail.main([path, "--json"])
        finally:
            sys.stdout = old
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(buf.getvalue())["matches"][0]["label"], "cli")
        sys.stdout = io.StringIO()
        try:
            rc_unknown = wail.main([self.write_image("u.img", bytearray(4096))])
            rc_text = wail.main([path, "-o", "0"])
        finally:
            sys.stdout = old
        self.assertEqual(rc_unknown, 1)
        self.assertEqual(rc_text, 0)
        err = io.StringIO()
        old_err = sys.stderr
        sys.stderr = err
        try:
            rc_missing = wail.main([os.path.join(self.tmp, "does-not-exist")])
        finally:
            sys.stderr = old_err
        self.assertEqual(rc_missing, 2)

    def test_parse_size(self):
        self.assertEqual(wail._parse_size("1M"), 1 * MiB)
        self.assertEqual(wail._parse_size("2048s"), 1 * MiB)
        self.assertEqual(wail._parse_size("0x1000"), 4096)
        self.assertEqual(wail._parse_size("3KiB"), 3072)


# --------------------------------------------------------------------------
# Real images built with macOS tools (opt-in)
# --------------------------------------------------------------------------

def _sh(*cmd):
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


@unittest.skipUnless(sys.platform == "darwin" and shutil.which("hdiutil") and os.environ.get("WAIL_REAL_TESTS"),
                     "set WAIL_REAL_TESTS=1 on macOS to build real images with hdiutil")
class RealMacImages(ImageCase):
    def make(self, name, fs, volname, layout="NONE", size="16m"):
        path = os.path.join(self.tmp, name)
        _sh("hdiutil", "create", "-size", size, "-fs", fs, "-volname", volname, "-layout", layout, "-o", path, "-quiet")
        return path

    def test_hfsplus_journaled(self):
        m = self.assertFS(wail.identify_path(self.make("h.dmg", "HFS+J", "RealHFS")), "hfsplus", "RealHFS")
        self.assertIn("journaled", m["details"]["state"])

    def test_hfsx(self):
        self.assertFS(wail.identify_path(self.make("hx.dmg", "Case-sensitive HFS+", "RealHFSX")), "hfsx", "RealHFSX")

    def test_fat32_exfat(self):
        self.assertFS(wail.identify_path(self.make("f.dmg", "MS-DOS FAT32", "REALFAT", size="64m")), "fat32", "REALFAT")
        self.assertFS(wail.identify_path(self.make("e.dmg", "ExFAT", "REALEXFAT", size="64m")), "exfat", "REALEXFAT")

    def test_apfs_in_gpt(self):
        res = wail.identify_path(self.make("a.dmg", "APFS", "Real APFS", layout="GPTSPUD", size="100m"))
        t = res["partition_table"]
        self.assertEqual(t["scheme"], "gpt")
        self.assertEqual(t["partitions"][0]["type"], "Apple APFS")
        apfs = t["partitions"][0]["content"]["matches"][0]
        self.assertEqual(apfs["type"], "apfs")
        self.assertEqual(apfs["details"]["checkpoint"], "latest checkpoint")
        self.assertEqual([v["name"] for v in apfs["details"]["volumes"]], ["Real APFS"])

    def test_apm_and_mbr(self):
        res = wail.identify_path(self.make("apm.dmg", "HFS+", "APMReal", layout="SPUD"))
        self.assertEqual(res["partition_table"]["scheme"], "apm")
        self.assertEqual(res["partition_table"]["partitions"][1]["content"]["matches"][0]["label"], "APMReal")
        res = wail.identify_path(self.make("mbr.dmg", "MS-DOS FAT32", "MBRREAL", layout="MBRSPUD", size="64m"))
        self.assertEqual(res["partition_table"]["scheme"], "mbr")
        self.assertEqual(res["partition_table"]["partitions"][0]["content"]["matches"][0]["label"], "MBRREAL")

    def test_hybrid_iso_udf(self):
        src = os.path.join(self.tmp, "src")
        os.makedirs(src, exist_ok=True)
        with open(os.path.join(src, "hello.txt"), "w") as f:
            f.write("hello\n")
        out = os.path.join(self.tmp, "hybrid.iso")
        _sh("hdiutil", "makehybrid", "-iso", "-joliet", "-udf", "-default-volume-name", "HYBRID", "-o", out, src, "-quiet")
        res = wail.identify_path(out)
        self.assertEqual([m["type"] for m in res["matches"]], ["iso9660", "udf"])
        self.assertEqual(res["matches"][0]["label"], "HYBRID")
        self.assertEqual(res["matches"][1]["label"], "HYBRID")

    @unittest.skipUnless(os.environ.get("WAIL_DEVICE_TESTS"), "set WAIL_DEVICE_TESTS=1 to attach a disk image as a block device")
    def test_attached_block_device(self):
        path = self.make("dev.dmg", "HFS+J", "DevTest", layout="GPTSPUD", size="32m")
        out = _sh("hdiutil", "attach", "-nomount", path)
        whole = out.split()[0]
        try:
            for dev in (whole, whole.replace("/dev/disk", "/dev/rdisk")):
                res = wail.identify_path(dev)
                self.assertEqual(res["device_size"], 32 * MiB, dev)
                self.assertEqual(res["partition_table"]["scheme"], "gpt", dev)
                self.assertEqual(res["partition_table"]["partitions"][0]["content"]["matches"][0]["label"], "DevTest", dev)
        finally:
            subprocess.run(["hdiutil", "detach", whole], capture_output=True)


if __name__ == "__main__":
    unittest.main()
