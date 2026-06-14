# AGENTS.md — RTL9210B Firmware & Decloning Project

## Environment

- **Enclosure**: Sabrent USB 3.2 NVMe enclosure (Realtek RTL9210B-CG,
  `idVendor=0bda, idProduct=9210`)
- **Current firmware**: Unknown revision (likely older than v1.32; INQUIRY reports `1.00` but this is not the firmware version — confirmed from `dump/sabrent.txt` where FW 1.25.7 also shows INQUIRY revision `1.00`)
- **USB protocol**: BOT (Bulk-Only Transport, `bInterfaceProtocol=0x50`); kernel driver: `usb-storage` (required manual bind via `/sys/bus/usb/drivers/usb-storage/new_id`)
- **System**: Arch Linux, kernel 7.0.10-zen1-1-zen, `doas` not `sudo`

## Issues Encountered During Decloning

### Symptom 1: Drive disappears under sustained read load

Running `rsync -aviS` to copy ~168 GiB / 73K files from a **Samsung 970 EVO Plus
1TB** in this enclosure to the host caused the drive to silently unmount
mid-transfer. The block device (`/dev/sdb`) disappears entirely, while a stale
mount entry remains. The mount point returns `Input/output error`.

### Symptom 2: Millions of read I/O errors

- `btrfs device stats`: `read_io_errs` reached **1.36 million** during the
  failed transfer
- `corruption_errs`: 594 checksum mismatches (from bridge returning zeroed/null
  data during disconnects)
- Every file read across all directories (`career/`, `encrypted/`,
  `health-insurance/`, `tax-docs/`, `personal-finance/`) fails with
  `Input/output error (5)`
- Raw block device reads (`dd if=/dev/sdb2`) also fail

### Symptom 3: Works for short bursts, fails under sustained load

- Short transfers (1,147 files) succeed
- Sustained transfers (~72 GB over 8 minutes) trigger bridge failure
- After failure, power cycle (unplug/replug) restores functionality

### Symptom 4: Same enclosure works with different SSD

The **WD_BLACK SN770 500GB** in this same enclosure completed a 4.7 GB sustained
read test at ~970 MB/s with zero errors. The Samsung 970 EVO Plus 1TB triggers
the bridge firmware bug.

## Root Cause: RTL9210B Bridge Firmware Bug

Multiple independent sources confirm the Realtek RTL9210B has firmware-level
bugs causing disconnects under sustained load, particularly with certain SSD
models:

| Source                             | Details                                                                                                                                           |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| Station-Drivers firmware changelog | v1.32.68: "addresses USB link instability seen in some SSD models when used in conjunction with Linux-based PCs, including the Solidigm P41 Plus" |
| Station-Drivers v1.29.12           | "Fix Compatibility with Samsung M.2 SSDs"                                                                                                         |
| Station-Drivers v1.27.25           | "aims to improve stability with Samsung 980 Pro and Western Digital SN550 NVMe SSDs"                                                              |
| Raspberry Pi kernel issue #7080    | Realtek RTL9210 disconnects during rsync/Docker/rpi-clone; confirmed fixed by firmware update                                                     |
| Sabrent forums (EC-SNVE)           | Random disconnects during file copy operations; `U1/U2 failed` errors in dmesg                                                                    |
| OCAU forums                        | All 3 RTL9210 enclosures disconnect under sustained writes; firmware update resolves                                                              |

The issue manifests as USB link state transition failures (`U1`/`U2` power
management states). The bridge drops off the USB bus, the kernel returns EIO to
the block layer, and btrfs records `read_io_errs`. The SSD itself is not
degrading — the `corruption_errs` are artifacts of the bridge returning garbage
during disconnect/reconnect cycles.

## How bensuperpc/rtl9210 Relates

This repository (`~/repos/pngdeity/rtl9210`) is a clone of
[bensuperpc/rtl9210](https://github.com/bensuperpc/rtl9210), which archives
Realtek RTL9210/B firmware updates and configuration tools. It provides:

- **Firmware binaries**: Multiple versions from v1.23 through latest
- **Configuration files**: Per-enclosure model configs (including Sabrent
  EC-SNVE)
- **Firmware update tools**: Windows-based `UTHSB_MPtool` for flashing
- **Unbrick procedures**: SPI pin-shorting method for recovery from failed
  flashes
- **Known-working firmware versions**: v1.32.49+ confirmed to fix Samsung SSD
  instability

### Relevant firmware versions

| Version            | Notes                                                           |
| ------------------ | --------------------------------------------------------------- |
| v1.23.9 (2020-10)  | Very old — likely has Samsung compatibility bugs                |
| v1.27.25 (2021-07) | "improve stability with Samsung 980 Pro and WD SN550"           |
| v1.29.12 (2022-01) | "Fix Compatibility with Samsung M.2 SSDs"                       |
| v1.32.49 (2023-04) | Post-dates the Samsung 980 Pro fix era                          |
| v1.32.68 (2023-06) | "addresses USB link instability... including Solidigm P41 Plus" |
| v1.32.87 (2023-08) | Latest in repo (> v1.34.39 available, not yet tested on this enclosure) |

## Reverse Engineering: UTHSB_MPtool_Lite.exe

Goal: extract the firmware update protocol to enable a native Linux flasher.

### Pipeline (`.devcontainer/` + `scripts/`)

| Component | Status | Notes |
|-----------|--------|-------|
| Ghidra decompilation | Working | 32,983 functions from v2.0.2.30818 (bundled with fw v1.34.39) |
| `setup.py` | Working | Ghidra 12.1, JDK 21, pyghidra 3.1.0 offline install, `chmod +x` on decompiler binary |
| `decompile.py` | Working | `--skip-ghidrecomp` for fast iteration. Steps 2-5 complete in ~10 min |
| `scan_patterns.py` | Working but noisy | 4,784 matches, 96% false positives (`0x12` as struct offsets) |
| `filter_decomp.py` | Partial | 205 files captured discovery layer but missed firmware write layer |
| `trace_scsi.py` | Broken | Detects 0x3B/0x3C in exception-state tokens, not real CDBs. Misses actual vendor opcode 0xE3 |
| `decomp_all.tar.gz` | Working | 73 MB LFS-tracked tarball for reproducible extraction |

### Key Functions (verified roles)

| Function | Address | Role | Location |
|----------|---------|------|----------|
| `FUN_00c244f0` | `0x00c244f0` | SCSI pass-through wrapper — builds `SCSI_PASS_THROUGH_DIRECT` (0x4D014) or `SCSI_PASS_THROUGH` (0x4D004) structures. CDB at offset +0x30, data at +0x50. Handles alignment for transfers ≥ 4KB | `decomp_all/` |
| `FUN_00c24250` | `0x00c24250` | Thin parameter-reordering wrapper for FUN_00c244f0 | `decomp_all/` |
| `FUN_00c241e0` | `0x00c241e0` | SCSI INQUIRY — constructs 12-byte CDB (opcode 0x12, allocation length 36). Debug string: "InquiryProperty" | `decomp_all/` |
| `FUN_00c258f0` | `0x00c258f0` | Vendor SCSI CDB constructor — builds 16-byte CDB with **opcode 0xE3** (vendor-specific), mode byte, and payload. Passes to FUN_00c24250 | `decomp_all/` |
| `FUN_00c257f0` | `0x00c257f0` | Mirror of FUN_00c258f0 — builds 16-byte CDB with **opcode 0xE2** (vendor read), magic byte 0xA8. Used for read/status queries via mode byte 0x13 | `decomp_all/` |
| `FUN_00c25ad0` | `0x00c25ad0` | ATA security orchestrator — take_ownership (mode 0x03), activate_locking_sp (0x04), locking_range_setup (0x08), set_mbr_enable (0x0C) | `decomp_all/` |
| `FUN_00c25f50` | `0x00c25f50` | Mode 0x10 wrapper — 8-line direct call to FUN_00c258f0 | `decomp_all/` |
| `FUN_00c25d10` | `0x00c25d10` | Mode 0x11 — 0x25-byte payload | `decomp_all/` |
| `FUN_00c25ca0` | `0x00c25ca0` | Mode 0x12 — 0x48-byte payload | `decomp_all/` |
| `FUN_00c2a220` | `0x00c2a220` | Device identification query — opens `CreateFileA`, sends IOCTL 0x2D1080 (no input, 12-byte output), returns success/failure | `relevant_decomp/` |
| `FUN_00c2aab0` | `0x00c2aab0` | Device enumerator — uses `SetupDiGetClassDevsW(GUID_DEVINTERFACE_DISK)`, queries each disk with 0x2D1080, matches VID/PID, resolves `\\.\PhysicalDriveX` paths | `relevant_decomp/` |
| `FUN_00c27f60` | `0x00c27f60` | USB descriptor reader — two-phase protocol: 6-byte handshake (IOCTL 0x220424) → variable-size data transfer | `relevant_decomp/` |
| `FUN_00c284f0` | `0x00c284f0` | USB hub descriptor reader — uses IOCTL 0x220408 (76-byte query/response) and 0x220454 (77-byte). Called from FUN_00c27f60 | `relevant_decomp/` |
| `FUN_0041f530` | `0x0041f530` | **Qt UI handler** — initializes actionUpdate_Mode, actionUpdate, actionUpdate_Steps, etc. Does NOT contain SCSI CDB construction. The 0x3B/0x3C values here are C++ exception cleanup-state tokens (values 59, 60 in a sequence 0x2C→0x3A→0x3B→0x3C→...), NOT WRITE BUFFER/READ BUFFER opcodes | `relevant_decomp/` |
| `FUN_0041d170` | `0x0041d170` | Qt main window — "Firmware Update", "Firmware Flash" UI setup | `relevant_decomp/` |
| `FUN_00c20e40` | `0x00c20e40` | **Firmware SPI flash write** — reads flash (FUN_00c21f50), writes address (cmd 0x10 via FUN_00c22500), writes data (cmd 0x11 via FUN_00c22500). Debug: "Write addr fail.", "Write data fail." | `decomp_all/` |
| `FUN_00c22500` | `0x00c22500` | **Write dispatcher** — sends vendor SCSI CDBs for SPI flash commands (0x10=set address, 0x11=write data, 0x30=force USB2, 0x4B=unknown). **Ghidra decomp FAILED** ("Cannot properly adjust input varnodes") | `decomp_all/` |
| `FUN_00c21fe0` | `0x00c21fe0` | SPI flash read wrapper — builds 0xE2 CDB with RTK_CMD from caller. Debug: "SptiUsb_p::read_flash" | `decomp_all/` |
| `FUN_00c21f50` | `0x00c21f50` | SPI flash read — hardcoded RTK_CMD=0x92. Debug: "SptiUsb_p::read_flash" | `decomp_all/` |
| `FUN_00c22240` | `0x00c22240` | SCSI command dispatcher — sends 0xE2+0xD1 quirks check first, then dispatches actual command via FUN_00c20ce0. Debug: "SptiUsb_p::_get_spti_cmdquirks" | `decomp_all/` |
| `FUN_00c20ce0` | `0x00c20ce0` | Generic SCSI CDB dispatcher — FNV-1a hashes CDB opcode, looks up in unordered_map, calls FUN_00c24250 | `decomp_all/` |

### SCSI Dispatch Architecture

```
Qt UI: FUN_0041f530 (actionUpdate, actionUpdate_Steps)
  → [Qt slot — not yet identified]
    → FUN_00c20e40 (SPI flash write orchestrator)
        ├── FUN_00c21f50 (read_flash: 0xE2+0x92 — verify before write)
        ├── FUN_00c22500(cmd=0x10, offset, 4)  — set SPI address
        └── FUN_00c22500(cmd=0x11, size, data)  — write SPI data

Alternate read path:
FUN_00c22240 (quirks: 0xE2+0xD1 → command support?)
  → FUN_00c20ce0 (FNV-1a hash lookup, generic dispatch)
    → FUN_00c24250 (thin parameter-reorder wrapper)
      → FUN_00c244f0 (SCSI_PASS_THROUGH_DIRECT → DeviceIoControl)
```

**RTK_CMD** (magic byte at CDB[4] for 0xE2 reads):

| Value | Operation | Source |
|-------|-----------|--------|
| 0x92 | Read SPI flash data | FUN_00c21f50 |
| 0xCB | Flash status/compare | FUN_00c21d70 |
| 0xD1 | Device quirks check (command support?) | FUN_00c22240 |
| 0xA8 | Read status query | FUN_00c257f0 |

**FUN_00c22500** command codes (SPI flash operations):

| Code | Operation | From |
|------|-----------|------|
| 0x10 | Set SPI flash address | FUN_00c20e40 (firmware write) |
| 0x11 | Write data to SPI flash | FUN_00c20e40 (firmware write) |
| 0x30 | Force USB 2.0 mode | FUN_00c234c0 |
| 0x4B | Retry after read mismatch | FUN_00c21d70 |

### IOCTL Catalog

| IOCTL Code | Decoded As | Purpose | Transport |
|-----------|------------|---------|-----------|
| `0x2D1080` | `CTL_CODE(0x2D, 0x420, METHOD_BUFFERED, FILE_ANY_ACCESS)` | Query device ID — no input, 12-byte response (vid/pid + device ID) | Vendor — Realtek device type 0x2D |
| `0x220424` | Vendor | Read USB descriptor — 6-byte handshake, then variable-size data | Vendor |
| `0x220408` | Vendor | Read/write USB hub descriptor — 6-byte query then variable-size; also used with 76-byte input for writes | Vendor |
| `0x220454` | Vendor | Read USB hub port config — 77-byte query/response | Vendor |
| `0x4D004` | `IOCTL_SCSI_PASS_THROUGH` | Standard SCSI command — used for INQUIRY and vendor commands | Standard (→ Linux SG_IO) |
| `0x4D014` | `IOCTL_SCSI_PASS_THROUGH_DIRECT` | Standard SCSI with direct data buffer | Standard (→ Linux SG_IO) |

The vendor IOCTLs handle device discovery and USB topology. The firmware write path uses **standard SCSI pass-through** (0x4D004/0x4D014) with vendor CDBs — no proprietary IOCTL on the critical path.

### Protocol Findings

**CDB construction pattern**: The tool builds SCSI CDBs on the stack as a length-prefixed byte array. Byte 0 = CDB length, bytes 1-16 = CDB data. The struct is passed to FUN_00c244f0 which copies it into a `SCSI_PASS_THROUGH_DIRECT` buffer at offset +0x30.

**INQUIRY CDB** (FUN_00c241e0):
```
Byte 0: 0x0C (CDB length = 12)
Bytes 1-6: 12 00 00 00 24 00  (INQUIRY, allocation length 36)
Bytes 7-12: 00 00 00 00 00 00 (padding)
```

**Vendor command CDB** (FUN_00c258f0):
```
Byte 0: 0x10 (CDB length = 16)
Byte 1: 0xE3 (vendor-specific opcode — NOT standard WRITE BUFFER 0x3B!)
Bytes 2-4: 0x00 (reserved — zero bytes from CONCAT14 low part)
Byte 5: 0x27 (fixed magic constant — high byte of CONCAT14(param_2, 0x27000000))
Byte 6: 0x00 (reserved)
Byte 7: param_2 (mode byte — multiplexes command type)
Bytes 8-15: transfer_length and parameters (encoded via shifts and CONCAT14)
```

**Verified 0xE3 mode bytes** (ATA security operations via FUN_00c25ad0):
| Mode | Operation | Payload Size |
|------|-----------|-------------|
| 0x03 | take_ownership | 0x24 (36) |
| 0x04 | activate_locking_sp | 0x34 (52) |
| 0x08 | locking_range_setup | 0x48 (72) |
| 0x0C | set_mbr_enable | 0x2C (44) |

Additional modes in thin wrappers: 0x10 (FUN_00c25f50, variable payload), 0x11 (FUN_00c25d10, 0x25 bytes), 0x12 (FUN_00c25ca0, 0x48 bytes), 0x13 (FUN_00c257f0, 0x48 bytes — status query).

The firmware WRITE/READ mode bytes are not yet identified. Candidates: 0x01, 0x02, 0x05, 0x06, 0x07, 0x0E, 0x0F. Will be found by searching for callers of FUN_00c258f0 with large data buffers (firmware .bin contents).

**SPI flash layout** (from station-drivers post #2452 by "ax, dx"):
| Offset | Content |
|--------|---------|
| 0x0000 | Empty (zeros) |
| 0x4000 | Main firmware header (from UTNVME) |
| 0x4800 | Configuration (TLV-encoded) |
| 0xC700 | Bootloader header (from UTGDFW/Golden firmware) |
| 0x13000 | Bootloader code |
| 0x20000 | Main firmware code |

### Dead Ends / False Leads

- **0x3B/0x3C in FUN_0041f530**: C++ exception handling cleanup-state tokens, NOT WRITE BUFFER/READ BUFFER opcodes. Confirmed by reading surrounding context — values are sequential UI event IDs.
- **Vendor IOCTLs as firmware path**: IOCTLs 0x2D1080/0x220424/0x220408/0x220454 handle USB device discovery and hub enumeration only, not firmware transfer.
- **trace_scsi.py CDB extraction**: Captured 1,314 "CDB extractions" but all have empty `cdb_assignments`. Pattern matching on 0x3B/0x3C produces 96% false positives from struct offsets, semicolons, and exception tokens.
- **Standard WRITE BUFFER (0x3B)**: The firmware flash uses vendor opcode 0xE3, not standard SCSI WRITE BUFFER. Standard sg3_utils `sg_write_buffer` will not work.
- **No public protocol docs**: Station-drivers post #2452 is the only reverse-engineering source. No USB packet captures exist. No Linux flasher exists (confirmed across fwupd, bensuperpc, Raspberry Pi communities).

### Hardware Testing (Phase 0-1)

**Enclosure**: Sabrent RTL9210B, attached via USB-C, no SSD inserted during testing.

**USB topology**: Bus 003 (USB 2.0, 480M), endpoints: Bulk IN 0x81, Bulk OUT 0x02 (512-byte max packet).

**SCSI transport** (`sg_raw.py` via `fcntl.ioctl(SG_IO)` on `/dev/sdb`):

| Command | Result |
|---------|--------|
| INQUIRY (0x12) | vendor=Sabrent, revision=1.00 |
| VPD 0x80 (Unit Serial) | serial=123400000012 |
| VPD 0x83 (Device ID) | 8-byte NAA identifier |
| VPD 0xB0 (Block Limits) | max transfer 256 blocks, optimal 128 |
| 0xE2 @ CDB[4]=0xA8 | Bridge recognizes opcode, rejects with ASC=0x24 (INVALID FIELD IN CDB) |
| 0xE2 magic elsewhere | ASC=0x20 (INVALID COMMAND OPERATION CODE) |
| 0xE3 (all variants) | ASC=0x20 (INVALID COMMAND OPERATION CODE) — bridge does not recognize |

**Key finding**: Magic byte position confirmed at CDB[4] (matches decompilation of CONCAT14 encoding). Mode byte and transfer length fields are not the rejection cause — the bridge rejects ALL 0xE2 CDBs with the same ASC=0x24 regardless of those fields. This means either a pre-condition is required (enter update mode command, erase), an additional check field exists in the CDB that we haven't decoded, or the bridge firmware revision "1.00" is too old to support vendor flashing via SCSI.

### Hardware Testing (Phase 2 — CDB field validation)

**Root cause found**: The bridge firmware is too old. ASC=0x24 was caused by **zero transfer length** (CDB[9-12]=0). All prior tests used `-l 0` in sg_raw.py.

**Verified CDB validation rules** (on firmware "1.00"):

| CDB | Len | Result | Conclusion |
|-----|-----|--------|------------|
| E2+A8 mode=0 | 0 | ASC=0x24 | Zero transfer length triggers INVALID FIELD |
| E2+A8 mode=0 | 72 | host=5 (DID_ABORT) | **Accepted** — data phase fails with no SSD inserted |
| E2+A8 mode=0x13 | 72 | host=5 | Mode byte not validated |
| E2+A8 mode=0x13 | 0 | ASC=0x24 | Confirms: only transfer length causes rejection |
| E2+0xD1 | 1 | ASC=0x20 | Magic 0xD1 not in opcode table |
| E2+0x92 | 256 | ASC=0x20 | Magic 0x92 not in opcode table |
| E3+0x27 | 36 | ASC=0x20 | 0xE3 not in opcode table at all |

**Hardware validation rules**: 0xE2 accepted IFF CDB[4]=0xA8 AND CDB[9-12]≠0. Mode byte and other CDB fields are unchecked. 0xE3 rejected unconditionally (ASC=0x20). Non-0xA8 0xE2 magic bytes also rejected (ASC=0x20). Bridge firmware "1.00" predates vendor command support for write opcodes and read magic bytes other than 0xA8.

### Test Script Inventory

| Script | Path | Purpose | Status |
|--------|------|---------|--------|
| `sg_inquiry.py` | `scripts/` | SCSI INQUIRY via SG_IO on block device | Working |
| `sg_raw.py` | `scripts/` | Generic SCSI CDB sender with `SG_IO` v3 ctypes, sense decoding, direction control | Working |
| `phase1_test.sh` | `scripts/` | Batch vendor CDB testing — magic position, mode byte, transfer length variants (15 test cases) | Working |
| `phase1b_test.sh` | `scripts/` | Transfer-length-encoded CDB variant tests | Working |
| `bsg_send.py` | `scripts/` | BSG raw write/read interface (`sg_io_v4` structure) | Broken (packing errors, permission denied) |
| `uasp_probe.py` | `scripts/` | UASP raw USB probe via pyusb | Wrong protocol — device uses BOT not UASP |

### Linux Flasher Implications

The firmware write uses **standard SCSI pass-through** (0x4D004/0x4D014 → Linux `SG_IO` ioctl). This means:

1. **No kernel driver needed**. Linux `SG_IO` via `/dev/sg*` can send the 0xE3 vendor CDB directly.
2. **SG_IO transport confirmed working** on this hardware. Standard SCSI commands (INQUIRY, VPD pages) complete successfully via `fcntl.ioctl(SG_IO)`. Vendor CDBs reach the bridge (host_status=0) but are rejected at the SCSI level — see Hardware Testing section.
3. **Windows USB capture** (usbmon + Wireshark) would give ground truth, needing only the mode byte and payload structure verified.

Remaining unknowns before a working flasher:
- Firmware write mode byte (which 0xE3 mode = write firmware to flash)
- Firmware read/verify mode byte
- Chunking strategy (max chunk size per command, offset encoding)
- GD firmware vs main firmware sequencing
- Pre-write handshake (enter update mode? erase sectors?)
- Post-write verification (CRC check? read-back compare?)
- **Current blocker**: Bridge firmware "1.00" predates vendor command support for 0xE3 writes and non-0xA8 0xE2 reads. 0xE2+0xA8 read works (with non-zero transfer length) but 0xE3 write is unrecognized. Must flash newer firmware first via Windows tool or CH341A programmer before vendor CDBs can be validated.
