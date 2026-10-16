#!/usr/bin/env python3
"""Prepare and boot the exact COS regression kernel with supplied test fixtures.

Requires Python 3, qemu-system-x86_64, KVM access, and mkfs.ext4. The initrd and
fixture disk come from the accompanying evidence archive; inspect guest.sh there
before running. Guest output is evidence to review, not an automatic test pass.
"""
import argparse
import base64
import bz2
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import urllib.request
import zlib
import lzma

URL = 'https://storage.googleapis.com/cos-tools/18867.624.2/cos_full_payload_stable.bin'
EXPECTED = {
    'kernel': 'e821cec8c0beb62b2b4ea61bc63afbdce7449b9634e0bd791bd4b28edda4bc14',
    'root': '77fb2cb94838dbb12c5585ff2d6e77474541804e772ff69a6456ca193d648e26',
}


def varint(data, offset):
    value = shift = 0
    while True:
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        shift += 7
        if byte < 128:
            return value, offset
        if shift > 63:
            raise ValueError('invalid protobuf varint')


def fields(data):
    offset = 0
    while offset < len(data):
        key, offset = varint(data, offset)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, offset = varint(data, offset)
        elif wire == 2:
            length, offset = varint(data, offset)
            value = data[offset:offset + length]
            offset += length
        else:
            raise ValueError(f'unsupported protobuf wire type {wire}')
        yield number, value


def require(condition, message):
    if not condition:
        raise ValueError(message)


def prepare(payload, work):
    data = payload.read_bytes()
    digest = base64.b64encode(hashlib.md5(data).digest()).decode()
    require(digest == 'hl91B9GxQQ/T4mZr/MJNGg==', 'unexpected COS payload MD5')
    magic, version, length, signature = struct.unpack('>4sQQI', data[:24])
    require(magic == b'CrAU' and version == 2, 'unexpected update payload header')
    start = 24 + length + signature
    manifest = list(fields(data[24:24 + length]))
    block = dict(manifest)[3]
    for tag, partition in manifest:
        if tag != 13:
            continue
        entries = list(fields(partition))
        values = dict(entries)
        name = values[1].decode()
        require(name in EXPECTED, f'unexpected partition {name}')
        info = dict(fields(values[7]))
        target = work / (name + '.img')
        with target.open('xb') as output:
            output.truncate(info[1])
            for number, raw in entries:
                if number != 8:
                    continue
                operation = list(fields(raw))
                op = dict(operation)
                content = data[start + op[2]:start + op[2] + op[3]]
                if 8 in op:
                    require(hashlib.sha256(content).digest() == op[8], 'operation checksum mismatch')
                content = {0: lambda x: x, 1: bz2.decompress, 8: lzma.decompress}[op[1]](content)
                offset = 0
                for field, extent in operation:
                    if field != 6:
                        continue
                    extent = dict(fields(extent))
                    size = extent[2] * block
                    output.seek(extent[1] * block)
                    output.write(content[offset:offset + size])
                    offset += size
                require(offset == len(content), 'unexpected operation length')
        digest = hashlib.sha256(target.read_bytes()).digest()
        require(digest == info[2] and digest.hex() == EXPECTED[name], 'partition checksum mismatch')
    kernel = (work / 'kernel.img').read_bytes()
    image = zlib.decompress(kernel[66252:], 31)
    require(image.startswith(b'\x7fELF'), 'vendor kernel is not ELF')
    require(hashlib.sha256(image).hexdigest() == 'b12ae2a84f196c94eda35658a1855813501fbe1b5d220408840bb7ff15395bff', 'kernel ELF checksum mismatch')
    (work / 'vmlinux').write_bytes(image)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir', required=True, type=Path, help='new directory; never reuse active VM disks')
    parser.add_argument('--payload', type=Path, help='existing payload; otherwise download exact public build')
    parser.add_argument('--initrd', required=True, type=Path)
    parser.add_argument('--fixtures', required=True, type=Path, help='prepared ext4 fixture image from evidence archive')
    parser.add_argument('--prepare-only', action='store_true')
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=False)
    payload = args.payload
    if payload is None:
        payload = work / 'payload.bin'
        urllib.request.urlretrieve(URL, payload)
    prepare(payload, work)
    shutil.copyfile(args.initrd, work / 'initrd.cpio')
    shutil.copyfile(args.fixtures, work / 'fixtures.img')
    with (work / 'state.img').open('xb') as disk:
        disk.truncate(24 * 1024**3)
    subprocess.run(['mkfs.ext4', '-F', str(work / 'state.img')], check=True)
    command = ['qemu-system-x86_64', '-enable-kvm', '-cpu', 'host', '-smp', '4', '-m', '4096',
               '-kernel', str(work / 'vmlinux'), '-initrd', str(work / 'initrd.cpio'),
               '-append', 'console=ttyS0 rdinit=/init panic=-1',
               '-drive', f'file={work}/root.img,format=raw,if=virtio,readonly=on',
               '-drive', f'file={work}/state.img,format=raw,if=virtio',
               '-drive', f'file={work}/fixtures.img,format=raw,if=virtio',
               '-netdev', 'user,id=n0', '-device', 'virtio-net-pci,netdev=n0',
               '-display', 'none', '-serial', f'file:{work}/serial.log', '-monitor', 'none', '-no-reboot']
    (work / 'qemu-command.json').write_text(json.dumps(command, indent=2) + '\n')
    print(f'Prepared {work}. Guest results remain in fixtures.img; inspect serial.log and mount read-only after shutdown.')
    if not args.prepare_only:
        subprocess.run(command, check=True)


if __name__ == '__main__':
    main()
