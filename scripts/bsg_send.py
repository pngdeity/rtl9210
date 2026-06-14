"""Send SCSI CDB via BSG write/read interface. Requires root (doas)."""

import argparse
import ctypes
import os
import struct
import sys


class SgioV4(ctypes.Structure):
    _fields_ = [
        ("guard", ctypes.c_int32),
        ("protocol", ctypes.c_int32),
        ("subprotocol", ctypes.c_uint32),
        ("request_len", ctypes.c_uint32),
        ("request", ctypes.c_uint64),
        ("request_tag", ctypes.c_uint64),
        ("request_attr", ctypes.c_uint32),
        ("request_priority", ctypes.c_uint32),
        ("request_extra", ctypes.c_uint64),
        ("max_response_len", ctypes.c_uint32),
        ("response", ctypes.c_uint64),
        ("dout_iovec_count", ctypes.c_uint32),
        ("din_iovec_count", ctypes.c_uint32),
        ("dout_xferp", ctypes.c_uint64),
        ("din_xferp", ctypes.c_uint64),
        ("dout_xfer_len", ctypes.c_uint32),
        ("din_xfer_len", ctypes.c_uint32),
        ("resid", ctypes.c_uint32),
        ("duration", ctypes.c_uint32),
        ("info", ctypes.c_uint32),
    ]


BSG_PROTOCOL_SCSI = 0
BSG_SUB_PROTOCOL_SCSI_CMD = 0


def bsg_send(device, cdb, alloc_len=256, timeout_ms=5000):
    fd = os.open(device, os.O_RDWR)
    try:
        cdb_buf = ctypes.create_string_buffer(bytes(cdb) + b"\x00" * (64 - len(cdb)))
        data_buf = ctypes.create_string_buffer(alloc_len) if alloc_len else None

        sgio = SgioV4()
        sgio.guard = ord("Q")
        sgio.protocol = BSG_PROTOCOL_SCSI
        sgio.subprotocol = BSG_SUB_PROTOCOL_SCSI_CMD
        sgio.request_len = len(cdb)
        sgio.request = ctypes.cast(cdb_buf, ctypes.c_void_p).value or 0
        sgio.max_response_len = alloc_len
        if data_buf and alloc_len:
            sgio.response = ctypes.cast(data_buf, ctypes.c_void_p).value or 0
        sgio.din_xfer_len = alloc_len
        sgio.din_iovec_count = 1 if alloc_len else 0

        written = os.write(
            fd, ctypes.string_at(ctypes.addressof(sgio), ctypes.sizeof(sgio))
        )
        if written != ctypes.sizeof(sgio):
            raise OSError(f"short write: {written}")

        nread = os.read(fd, ctypes.sizeof(sgio))
        if nread != ctypes.sizeof(sgio):
            raise OSError(f"short read: {nread}")

        result = SgioV4.from_buffer_copy(
            ctypes.string_at(ctypes.addressof(sgio), ctypes.sizeof(sgio))
        )

        data = (
            ctypes.string_at(data_buf, alloc_len - result.resid)
            if data_buf and alloc_len - result.resid > 0
            else b""
        )

        return {
            "status": result.info & 0xFF,
            "duration": result.duration,
            "resid": result.resid,
            "data": data,
        }
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description="Send SCSI CDB via BSG")
    parser.add_argument("cdb", help="hex CDB bytes")
    parser.add_argument(
        "-d",
        "--device",
        default="/dev/bsg/1:0:0:0",
        help="bsg device (default: /dev/bsg/1:0:0:0)",
    )
    parser.add_argument(
        "-l", "--length", type=int, default=256, help="allocation length (default: 256)"
    )
    args = parser.parse_args()

    if os.geteuid() != 0:
        parser.exit(1, "must run as root (doas)\n")

    cdb = bytes.fromhex(args.cdb)
    result = bsg_send(args.device, cdb, alloc_len=args.length)

    print(
        f"status={result['status']} resid={result['resid']} "
        f"duration={result['duration']}ms"
    )
    if result["data"]:
        print(f"data ({len(result['data'])}B): {result['data'].hex()}")
    return 0 if result["status"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
