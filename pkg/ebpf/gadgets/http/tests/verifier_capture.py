#!/usr/bin/env python3
"""Privileged BPF load and TCP iovec capture regression (Python standard library)."""

import argparse
import array
import fcntl
import json
import os
from pathlib import Path
import queue
import signal
import socket
import subprocess
import threading
import time


CHUNK = 16 * 1024
LIMIT = 16 * CHUNK


def connection():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        client = socket.socket()
        client.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 * LIMIT)
        client.connect(listener.getsockname())
        server, _ = listener.accept()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * LIMIT)
        return client, server


def syscall_name(event):
    value = event["syscall"]
    return bytes(value).split(b"\0", 1)[0].decode() if isinstance(value, list) else value


def wait_queued(sock, length):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        pending = array.array("i", [0])
        fcntl.ioctl(sock, 0x541B, pending)  # Linux FIONREAD
        if pending[0] >= length:
            return
        time.sleep(0.01)
    raise AssertionError(f"TCP fixture did not queue {length} bytes")


def exercise(mode, length, split, partial=False):
    header = b"POST /verifier-regression HTTP/1.1\r\nContent-Length: 500000\r\n\r\n"
    payload = (header + bytes(range(256)) * (length // 256 + 1))[:length]
    vectors = [b"", payload[:split], b"", payload[split:]] if split else [payload]
    client, server = connection()
    try:
        if mode in ("sendmsg", "writev"):
            transferred = client.sendmsg(vectors) if mode == "sendmsg" else os.writev(client.fileno(), vectors)
            fd = client.fileno()
        else:
            client.sendall(payload)
            wait_queued(server, length)
            capacity = length // 2 if partial else length
            first = min(split, capacity) if split else capacity
            buffers = [bytearray(), bytearray(first), bytearray(), bytearray(capacity - first)]
            transferred = (server.recvmsg_into(buffers)[0] if mode == "recvmsg"
                           else os.readv(server.fileno(), buffers))
            fd = server.fileno()
            assert transferred == capacity, (mode, transferred, capacity)
            assert b"".join(buffers)[:transferred] == payload[:transferred]
        if not partial:
            assert transferred == length, (mode, transferred, length)
        return client, server, fd, payload[:min(transferred, LIMIT)]
    except BaseException:
        client.close()
        server.close()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", help="Test an imported image instead of building current source")
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run as root to load and attach BPF")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    version = subprocess.check_output(["ig", "version"], text=True).strip()
    if version != "v0.48.1":
        parser.error(f"requires IG v0.48.1, found {version}")
    image = args.image or f"http:verifier-{os.getpid()}"
    (args.output_dir / "environment.json").write_text(json.dumps({
        "kernel": os.uname().release, "ig": version, "image": image,
    }, indent=2) + "\n")
    if not args.image:
        build = args.output_dir / "build"
        build.mkdir(exist_ok=True)
        subprocess.run(["ig", "image", "build", "-t", image, "-o", str(build),
                        str(Path(__file__).resolve().parents[1]),
                        "--builder-image-pull", "missing"], check=True)
    events = queue.Queue()
    with (args.output_dir / "events.jsonl").open("w") as output, (args.output_dir / "verifier.log").open("w") as log:
        tracer = subprocess.Popen(["ig", "run", image, "--host", "--pid", str(os.getpid()),
                                   "--pull", "never", "--verify-image=false", "--verbose",
                                   "--timeout", "120", "-o", "json"],
                                  stdout=subprocess.PIPE, stderr=log, text=True)

        def read_events():
            for line in tracer.stdout:
                output.write(line)
                output.flush()
                try:
                    events.put(json.loads(line))
                except json.JSONDecodeError:
                    events.put({"error": line})

        reader = threading.Thread(target=read_events, daemon=True)
        reader.start()

        def capture(mode, fd, expected, timeout=5):
            found = bytearray()
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if tracer.poll() is not None:
                    raise AssertionError(f"gadget exited {tracer.returncode}; see verifier.log")
                try:
                    event = events.get(timeout=0.1)
                except queue.Empty:
                    if found == expected:
                        return
                    continue
                assert "error" not in event, event
                if event["proc"]["pid"] != os.getpid() or event["sock_fd"] != fd or syscall_name(event) != mode:
                    continue
                size = event["buf_len"]
                assert 0 < size <= CHUNK, size
                found.extend(bytes(event["buf"])[:size])
                assert expected.startswith(found), f"{mode}: wrong captured payload"
            raise AssertionError(f"{mode}: captured {len(found)} of {len(expected)} bytes")

        try:
            # Require an actual sendmsg event before starting assertions. This
            # tolerates attach latency without treating process liveness as ready.
            deadline = time.monotonic() + 15
            while True:
                client, server, fd, expected = exercise("sendmsg", 128, 64)
                try:
                    capture("sendmsg", fd, expected, timeout=0.5)
                    break
                except AssertionError:
                    if tracer.poll() is not None or time.monotonic() >= deadline:
                        raise
                finally:
                    client.close()
                    server.close()
            for mode in ("sendmsg", "recvmsg", "writev", "readv"):
                for length in (CHUNK - 1, CHUNK, CHUNK + 1, LIMIT, LIMIT + 1):
                    for split in (0, 8192):
                        client, server, fd, expected = exercise(mode, length, split)
                        try:
                            capture(mode, fd, expected)
                            print(f"PASS {mode} bytes={length} split={split}", flush=True)
                        finally:
                            client.close()
                            server.close()
                if mode in ("recvmsg", "readv"):
                    client, server, fd, expected = exercise(mode, CHUNK + 1, 8192, partial=True)
                    try:
                        capture(mode, fd, expected)
                        print(f"PASS {mode} partial receive", flush=True)
                    finally:
                        client.close()
                        server.close()
        finally:
            if tracer.poll() is None:
                tracer.send_signal(signal.SIGINT)
            try:
                status = tracer.wait(timeout=10)
            except subprocess.TimeoutExpired:
                tracer.kill()
                tracer.wait()
                raise
            reader.join(timeout=5)
            tracer.stdout.close()
        assert status == 0, f"gadget exited {status}; see verifier.log"


if __name__ == "__main__":
    main()
