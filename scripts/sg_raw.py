"""Send arbitrary SCSI CDB via SG_IO. Requires root (doas)."""

import argparse
import ctypes
import fcntl
import os
import sys

SG_IO = 0x2285
SG_DXFER_FROM_DEV = -3
SG_DXFER_TO_DEV = -1
SG_DXFER_NONE = -3  # same as FROM for compatibility


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


SENSE_CODES = {
    0x00: "NO SENSE",
    0x02: "NOT READY",
    0x04: "HARDWARE ERROR",
    0x05: "ILLEGAL REQUEST",
    0x06: "UNIT ATTENTION",
    0x07: "DATA PROTECT",
    0x0B: "ABORTED COMMAND",
    0x20: "INVALID COMMAND OPERATION CODE",
    0x24: "INVALID FIELD IN CDB",
    0x25: "LOGICAL UNIT NOT SUPPORTED",
    0x26: "INVALID FIELD IN PARAMETER LIST",
}


def sg_send(
    device, cdb, direction=SG_DXFER_FROM_DEV, data_out=b"", alloc_len=0, timeout=5000
):
    fd = os.open(device, os.O_RDWR)
    try:
        dxfer_len = alloc_len
        if direction == SG_DXFER_TO_DEV:
            dxfer_len = len(data_out)

        data_buf = ctypes.create_string_buffer(max(dxfer_len, 1))
        sense_buf = ctypes.create_string_buffer(32)
        cdb_buf = ctypes.create_string_buffer(bytes(cdb))

        if direction == SG_DXFER_TO_DEV and data_out:
            ctypes.memmove(data_buf, data_out, len(data_out))

        sgio = SgioV3()
        sgio.interface_id = ord("S")
        sgio.dxfer_direction = direction
        sgio.cmd_len = len(cdb)
        sgio.mx_sb_len = 32
        sgio.dxfer_len = dxfer_len
        sgio.dxferp = ctypes.cast(data_buf, ctypes.c_void_p)
        sgio.cmdp = ctypes.cast(cdb_buf, ctypes.c_void_p)
        sgio.sbp = ctypes.cast(sense_buf, ctypes.c_void_p)
        sgio.timeout = timeout

        fcntl.ioctl(fd, SG_IO, sgio)

        sense = bytes(sense_buf[: sgio.sb_len_wr]) if sgio.sb_len_wr else b""
        data = (
            ctypes.string_at(sgio.dxferp, sgio.dxfer_len - sgio.resid)
            if (direction != SG_DXFER_NONE or sgio.dxfer_len > 0)
            else b""
        )

        return {
            "status": sgio.status,
            "host_status": sgio.host_status,
            "driver_status": sgio.driver_status,
            "resid": sgio.resid,
            "duration": sgio.duration,
            "sense": sense,
            "data": data,
        }
    finally:
        os.close(fd)


def format_sense(sense):
    if not sense or len(sense) < 14:
        return "(none)"
    key = sense[2] & 0xF
    asc = sense[12]
    ascq = sense[13]
    key_name = SENSE_CODES.get(key, f"0x{key:02X}")
    return f"key={key_name} ASC={asc:#04x} ASCQ={ascq:#04x}"


def main():
    parser = argparse.ArgumentParser(description="Send SCSI CDB via SG_IO")
    parser.add_argument("cdb", help="hex CDB bytes (e.g. 120000002400)")
    parser.add_argument(
        "-d", "--device", default="/dev/sdb", help="block device (default: /dev/sdb)"
    )
    parser.add_argument(
        "-D",
        "--direction",
        default="from",
        choices=["from", "to", "none"],
        help="data direction (default: from)",
    )
    parser.add_argument(
        "-l",
        "--length",
        type=int,
        default=256,
        help="allocation length for reads (default: 256)",
    )
    parser.add_argument(
        "-i", "--input", type=str, default="", help="hex data to send (direction=to)"
    )
    parser.add_argument(
        "-t", "--timeout", type=int, default=5000, help="timeout in ms (default: 5000)"
    )
    args = parser.parse_args()

    if os.geteuid() != 0:
        parser.exit(1, "must run as root (doas)\n")

    cdb = bytes.fromhex(args.cdb)
    direction = {"from": -3, "to": -1, "none": -3}[args.direction]
    data_out = bytes.fromhex(args.input) if args.input else b""

    result = sg_send(
        args.device,
        cdb,
        direction=direction,
        data_out=data_out,
        alloc_len=args.length,
        timeout=args.timeout,
    )

    ok = result["status"] == 0 and result["host_status"] == 0
    status = "OK" if ok else "FAIL"
    print(
        f"{status} status={result['status']} "
        f"host_status={result['host_status']} "
        f"driver_status={result['driver_status']} "
        f"resid={result['resid']} {result['duration']}ms"
    )
    print(f"sense: {format_sense(result['sense'])}")
    if result["sense"]:
        print(f"sense raw ({len(result['sense'])}B): {result['sense'].hex()}")
    if result["data"]:
        print(f"data ({len(result['data'])}B): {result['data'].hex()}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
