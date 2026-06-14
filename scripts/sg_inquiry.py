"""Send SCSI INQUIRY via SG_IO to a bsg device. Requires root (doas)."""

import argparse
import ctypes
import fcntl
import os

SG_IO = 0x2285
SG_DXFER_FROM_DEV = -3
SG_DXFER_TO_DEV = -2
SG_DXFER_NONE = -1


class SgioV3(ctypes.Structure):
    _fields_ = [
        ("interface_id", ctypes.c_int),
        ("dxfer_direction", ctypes.c_int),
        ("cmd_len", ctypes.c_ubyte),
        ("mx_sb_len", ctypes.c_ubyte),
        ("iovec_count", ctypes.c_ushort),
        ("dxfer_len", ctypes.c_uint),
        ("dxferp", ctypes.c_void_p),
        ("cmdp", ctypes.c_void_p),
        ("sbp", ctypes.c_void_p),
        ("timeout", ctypes.c_uint),
        ("flags", ctypes.c_uint),
        ("pack_id", ctypes.c_int),
        ("usr_ptr", ctypes.c_void_p),
        ("status", ctypes.c_ubyte),
        ("masked_status", ctypes.c_ubyte),
        ("msg_status", ctypes.c_ubyte),
        ("sb_len_wr", ctypes.c_ubyte),
        ("host_status", ctypes.c_ushort),
        ("driver_status", ctypes.c_ushort),
        ("resid", ctypes.c_int),
        ("duration", ctypes.c_uint),
        ("info", ctypes.c_uint),
    ]


def sg_inquiry(device_path):
    cdb = bytes([0x12, 0x00, 0x00, 0x00, 0x24, 0x00])
    fd = os.open(device_path, os.O_RDWR)
    try:
        data_buf = ctypes.create_string_buffer(36)
        sense_buf = ctypes.create_string_buffer(32)
        cdb_buf = ctypes.create_string_buffer(cdb)

        sgio = SgioV3()
        sgio.interface_id = ord("S")
        sgio.dxfer_direction = SG_DXFER_FROM_DEV
        sgio.cmd_len = len(cdb)
        sgio.mx_sb_len = 32
        sgio.dxfer_len = 36
        sgio.dxferp = ctypes.cast(data_buf, ctypes.c_void_p)
        sgio.cmdp = ctypes.cast(cdb_buf, ctypes.c_void_p)
        sgio.sbp = ctypes.cast(sense_buf, ctypes.c_void_p)
        sgio.timeout = 5000

        fcntl.ioctl(fd, SG_IO, sgio)
        data = ctypes.string_at(sgio.dxferp, sgio.dxfer_len - sgio.resid)

        print(
            f"status={sgio.status} host_status={sgio.host_status} "
            f"driver_status={sgio.driver_status} resid={sgio.resid}"
        )
        if sgio.status == 0 and sgio.host_status == 0:
            vendor = data[8:16].decode("ascii", errors="replace").strip()
            product = data[16:32].decode("ascii", errors="replace").strip()
            rev = data[32:36].decode("ascii", errors="replace").strip()
            print(f"vendor: {vendor}")
            print(f"product: {product}")
            print(f"revision: {rev}")
        else:
            sense = bytes(sense_buf[: sgio.sb_len_wr])
            print(f"sense: {sense.hex()}")
        return sgio.status
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description="Send SCSI INQUIRY via SG_IO")
    parser.add_argument(
        "device",
        nargs="?",
        default="/dev/sdb",
        help="block or sg device path (default: /dev/sdb)",
    )
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.exit(1, "must run as root (doas)\n")
    return sg_inquiry(args.device)


if __name__ == "__main__":
    raise SystemExit(main())
