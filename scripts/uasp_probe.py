"""Send vendor SCSI CDB via raw UASP. Requires root (doas)."""

import argparse
import os
import struct
import usb.core
import usb.util

# UASP IU types
IU_ID_COMMAND = 0x01
IU_ID_STATUS = 0x03
IU_ID_RESPONSE = 0x04
IU_ID_READ_READY = 0x06
IU_ID_WRITE_READY = 0x07

# Common IU header: iu_id(1) rsvd1(1) tag(2 BE) — 4 bytes packed
# Command IU: header + prio_attr(1) rsvd5(1) len(1) rsvd7(1) lun(8) cdb(16) = 32
# Sense IU:   header + status_qual(2) status(1) rsvd7(7) len(2) sense(var)
# Read/Write Ready IU: same first 4 bytes as Sense IU


def build_command_iu(cdb, tag=1, prio_attr=0):
    cdb_padded = bytes(cdb) + b"\x00" * (16 - len(cdb))
    lun = b"\x00" * 8  # scsi_lun, LUN 0
    return struct.pack(
        "<BBH BB B B 8s 16s",
        IU_ID_COMMAND,  # iu_id
        0,  # rsvd1
        tag,  # tag (big-endian in struct)
        prio_attr,  # prio_attr (0 = simple)
        0,  # rsvd5
        0,  # len (CDB addtl length)
        0,  # rsvd7
        lun,  # lun (8 bytes, LUN 0)
        cdb_padded,  # cdb[16]
    )


def parse_sense_iu(data):
    if len(data) < 16:
        return {"error": f"short sense: {len(data)}B"}
    iu_id, rsvd1, tag, status_qual, scsi_status = struct.unpack_from("<BB H H B", data)
    if len(data) >= 16:
        sense_len = struct.unpack_from(">H", data, 14)[0]
        sense = data[16 : 16 + min(sense_len, len(data) - 16)]
    else:
        sense_len = 0
        sense = b""
    return {
        "iu_id": iu_id,
        "tag": tag,
        "status_qual": status_qual,
        "scsi_status": scsi_status,
        "sense_len": sense_len,
        "sense": sense,
    }


def parse_response_iu(data):
    if len(data) < 8:
        return {"error": f"short response: {len(data)}B"}
    iu_id, rsvd1, tag = struct.unpack_from("<BBH", data)
    add_info = data[4:7]
    response_code = data[7]
    return {
        "iu_id": iu_id,
        "tag": tag,
        "response_code": response_code,
        "add_response_info": add_info,
    }


def uasp_command(dev, ep_out, ep_in, cdb, data_out=b"", alloc_len=0, timeout=5000):
    tag = 1
    cmd = build_command_iu(cdb, tag=tag)
    dev.write(ep_out, cmd, timeout=timeout)

    if data_out:
        dev.write(ep_out, data_out, timeout=timeout)
    elif alloc_len:
        pass  # data in handled below

    # Read response(s) from status pipe
    result = {"status": "unknown"}
    while True:
        raw = bytes(dev.read(ep_in, 1024, timeout=timeout))
        iu_id = raw[0] if raw else 0

        if iu_id == IU_ID_STATUS:
            result = parse_sense_iu(raw)
            break
        elif iu_id == IU_ID_WRITE_READY:
            if data_out:
                dev.write(ep_out, data_out, timeout=timeout)
        elif iu_id == IU_ID_READ_READY:
            if alloc_len:
                data = bytes(dev.read(ep_in, alloc_len, timeout=timeout))
                result["data"] = data
        elif iu_id == IU_ID_RESPONSE:
            riu = parse_response_iu(raw)
            result["response_code"] = riu.get("response_code")
            break
        else:
            result["error"] = f"unknown IU id=0x{iu_id:02x}, raw={raw[:32].hex()}"
            break

    return result


def main():
    parser = argparse.ArgumentParser(description="Send vendor SCSI CDB via raw UASP")
    parser.add_argument("cdb", help="hex CDB bytes")
    parser.add_argument(
        "-l",
        "--length",
        type=int,
        default=0,
        help="allocation length for reads (default: 0)",
    )
    args = parser.parse_args()

    if os.geteuid() != 0:
        parser.exit(1, "must run as root (doas)\n")

    cdb = bytes.fromhex(args.cdb)
    dev = usb.core.find(idVendor=0x0BDA, idProduct=0x9210)
    if dev is None:
        parser.exit(1, "RTL9210 not found\n")

    if dev.is_kernel_driver_active(0):
        dev.detach_kernel_driver(0)

    try:
        dev.set_configuration()
    except usb.core.USBError:
        pass

    cfg = dev.get_active_configuration()
    intf = cfg[(0, 0)]
    ep_out = usb.util.find_descriptor(
        intf,
        custom_match=lambda e: (
            usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT
        ),
    ).bEndpointAddress
    ep_in = usb.util.find_descriptor(
        intf,
        custom_match=lambda e: (
            usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN
        ),
    ).bEndpointAddress

    result = uasp_command(dev, ep_out, ep_in, cdb, alloc_len=args.length)

    scsi_status = result.get("scsi_status", None)
    if scsi_status is not None:
        print(f"scsi_status={scsi_status:#04x}")
    sense = result.get("sense", b"")
    if sense:
        key = sense[2] & 0xF if len(sense) > 2 else None
        asc = sense[12] if len(sense) > 12 else None
        ascq = sense[13] if len(sense) > 13 else None
        print(
            f"sense_key=0x{key:01x} asc=0x{asc:02x} ascq=0x{ascq:02x}"
            if key is not None
            else f"sense: {sense.hex()}"
        )
    data = result.get("data", b"")
    if data:
        print(f"data ({len(data)}B): {data.hex()}")
    if "error" in result:
        print(f"error: {result['error']}")
    rc = result.get("response_code")
    if rc is not None:
        print(f"response_code={rc:#04x}")

    return 0 if scsi_status == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
