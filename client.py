#!/usr/bin/env python3
"""
client.py - traffic generator so the per-request crash trigger has requests to chew on.
Sends mostly valid AUTH requests and occasionally malformed ones.
"""
import argparse
import random
import socket
import time

import common

CREDS = [("alice", "wonderland"), ("bob", "builder"), ("carol", "hunter2"), ("mallory", "guess")]
BAD = [b"AUTH", b"\xff\xfe\x00garbage", b"AUTH alice", b"A" * 1500, b"DROP TABLE users;"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rate", type=float, default=5.0, help="requests per second")
    ap.add_argument("--bad-frac", type=float, default=0.1, help="fraction of malformed requests")
    args = ap.parse_args()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.5)
    print(f"[client] sending ~{args.rate} req/s to {common.SERVICE_ADDR} (Ctrl-C to stop)")
    while True:
        if random.random() < args.bad_frac:
            payload = random.choice(BAD)
        else:
            u, p = random.choice(CREDS)
            payload = f"AUTH {u} {p}".encode()
        try:
            sock.sendto(payload, common.SERVICE_ADDR)
            reply, _ = sock.recvfrom(2048)
            print(f"[client] {payload[:30]!r} -> {reply.decode(errors='replace')}")
        except socket.timeout:
            print(f"[client] {payload[:30]!r} -> (no reply; service down?)")
        except OSError:
            print("[client] socket error (service down?)")
        time.sleep(1.0 / args.rate)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
