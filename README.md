# wail — What Am I Looking at?

A small, dependency-free Python command-line tool that tells you what
filesystem (or partition table, RAID/LVM/crypto container, or disk-image
format) is on a block device or in a disk-image file.

**Strictly read-only.** The target is opened `O_RDONLY`; the program never
issues a write. The only system calls made against the target are
`open`, `fstat`, `lseek`, `read`, a get-size `ioctl`, and `close`.

Pure standard library, Python 3.8+. Runs on macOS, Linux, the BSDs and
Windows (native or WSL). Only macOS has been tested in anger.

## Usage

```
python3 wail.py /dev/disk4           # macOS whole disk (needs root for real disks)
python3 wail.py /dev/rdisk4s2        # raw device, one partition
python3 wail.py /dev/sdb             # Linux
python3 wail.py \\.\PhysicalDrive1   # Windows (run as Administrator)
python3 wail.py disk.img other.img   # image files; several at once is fine
python3 wail.py -j disk.img          # JSON for scripts
python3 wail.py -o 1M part.img       # probe at a byte offset (K/M/G/T, or 2048s for sectors)
python3 wail.py -P disk.img          # don't descend into partition tables
```

Exit status: `0` something was identified, `1` nothing recognised, `2` a
target could not be opened or read.

Example output for a GPT-partitioned Mac disk image:

```
disk.dmg  (1.0 GiB, 1073741824 bytes)
  GPT partition table (primary header)
    sector size:  512
    uuid:         23C8C3EE-E016-4282-B109-F319CA33A3DC
  partition 1: Apple APFS "disk image"  @ 20.0 KiB, 1024.0 MiB
    uuid: 23931A41-6678-4198-9BC0-8A7F81D2AD99
      APFS container, version 2
        label:        "Macintosh HD", "Data"
        uuid:         ee3305c3-ad61-4711-9d1f-81e659f01079
        block size:   4096
        size:         1024.0 MiB (1073700864 bytes)
        checkpoint:   latest checkpoint
        volume 1: "Macintosh HD"
            uuid:        9f06d985-415f-47db-ab8c-fe3c168a0171
            role:        none
            attributes:  case-insensitive, unencrypted
        volume 2: "Data"
            ...
```

### Installing as a command

Nothing needs building; `wail.py` is self-contained and can be copied
anywhere. If you want a `wail` command on your `PATH`:

```
pip install .          # or: pipx install .
wail /dev/disk4
```

## What it recognises

| Family | Signatures |
| --- | --- |
| Linux | ext2 / ext3 / ext4 (and external journals), XFS, Btrfs, F2FS, JFS, ReiserFS 3.5/3.6, Reiser4, NILFS2, bcachefs, EROFS, OCFS2, GFS / GFS2, SquashFS, cramfs, romfs, Minix 1/2/3, UBIFS, JFFS2, swap (incl. hibernation images) |
| Windows / DOS / OS/2 | NTFS (with volume name and version from `$Volume`), FAT12 / FAT16 / FAT32 (label from the root directory), exFAT (label and volume GUID from the root directory), ReFS, HPFS, BitLocker and BitLocker To Go |
| Apple | APFS containers (newest checkpoint, every volume's name, UUID, role, case sensitivity and encryption via the object map), HFS+ and HFSX (label via the catalog file), classic HFS, HFS+ inside an HFS wrapper, Apple Partition Map, Apple UDIF `.dmg` trailers |
| ZFS / UFS | ZFS vdev labels (pool name, GUIDs, state, txg, hostname from the XDR nvlist), UFS1 / UFS2 in little- and big-endian layouts |
| Optical | ISO 9660 (with Joliet label and El Torito flag), UDF (with and without an ISO 9660 bridge) |
| Containers | LUKS1 / LUKS2, LVM2 physical volumes, Linux md RAID (0.90, 1.1, 1.2), VMware VMFS, BeFS/Haiku, Amiga FFS |
| Partition tables | GPT (primary or backup header, hybrid MBR detection), MBR with extended/logical partitions, Apple Partition Map, BSD disklabel (dedicated, or nested inside an MBR slice with slice-relative or absolute offsets) |
| "Not a raw image" | QCOW2, VMDK, VDI, VHD, VHDX, QED, Parallels, EnCase E01/L01, AFF, gzip / xz / bzip2 / zstd / zip / 7z / rar / tar |

Partition tables are descended into, so a whole-disk image reports every
partition and what is inside each. Weak two-byte signatures (Minix, JFFS2,
Amiga) are only reported when nothing stronger matched at the same offset.

## How it works

Every probe reads a handful of aligned 4 KiB blocks (the alignment is what
raw devices such as macOS `/dev/rdiskN` and Windows `\\.\PhysicalDriveN`
require) through a small caching reader, checks the on-disk magic number at
its documented offset, and then validates a few sanity fields before
reporting. Labels and UUIDs are pulled from the superblock when they live
there, and from the first metadata structure that holds them otherwise
(NTFS `$Volume`, FAT/exFAT root directory, HFS+ catalog, APFS object map and
volume superblocks, ZFS nvlist).

The library entry point is `wail.identify_path(path, offset=0,
partitions=True)`, which returns the same nested structure as `--json`.

## Tests

```
python3 -m unittest discover -s tests -v
```

The default suite builds synthetic images in a temporary directory: every
signature is laid down at its real offset, so each probe's offsets are
checked without needing `mkfs` tools. On macOS two more sets are opt-in:

```
WAIL_REAL_TESTS=1 python3 -m unittest discover -s tests -v    # hdiutil-built HFS+, HFSX, FAT32, exFAT, APFS, APM, MBR, ISO/UDF
WAIL_DEVICE_TESTS=1 WAIL_REAL_TESTS=1 python3 -m unittest discover -s tests -v   # also attaches an image and probes /dev/diskN and /dev/rdiskN
```

## Limitations

* APFS volume names come from the object map of the newest checkpoint whose
  checksum verifies; a container that is mid-write or damaged falls back to
  the block-0 superblock copy and reports only the volume count.
* HFS+ labels are read from the first leaf node of the catalog file's first
  extent. On a heavily fragmented catalog this can miss, in which case the
  filesystem is still identified but without a label.
* Encrypted APFS volumes are named (the volume superblock is in the clear),
  but nothing inside LUKS, BitLocker, FileVault or Core Storage is probed.
* Compressed or sparse image formats (QCOW2, VMDK, VDI, VHD/VHDX, UDZO `.dmg`)
  are recognised but not opened; convert them to raw first.
