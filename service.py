#!/usr/bin/env python3
"""
service.py - CRITICAL SERVICE: a minimal Authentication / Ticket Service.

Clients send UDP requests:   AUTH <user> <password>
Service replies:             TICKET <token>   or   DENIED
(Dummy credential store; the point of the project is the monitoring, not the auth logic.)

Heartbeat (PUSH model): a dedicated thread sends a HEARTBEAT datagram to the monitor
every T seconds. It is decoupled from request handling so a busy main thread does not
cause a false failover.

NON-DETERMINISTIC FAILURE (no hard-coded "crash on request #5"):
  1. Per-request random crash: every request has a small crash probability that grows with
     a simulated "memory leak" counter; malformed requests have a much higher probability
     (simulating an unhandled exception / memory-corruption bug on bad input).
  2. Background fault-injector thread: sleeps for a random exponentially-distributed time,
     then kills the process (simulating OOM-kill / segfault / external fault).
Both use os._exit(), which terminates the whole process immediately (no cleanup, no
sleeping) - exactly like a real crash.
"""
import argparse
import hashlib
import hmac
import os
import random
import socket
import sys
import threading
import time
import uuid

import common

USERS = {"alice": "wonderland", "bob": "builder", "carol": "hunter2"}  # dummy credential store
TICKET_KEY = os.urandom(16)  # per-boot key used to mint session tokens


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] [service pid={os.getpid()}] {msg}", flush=True)


def crash(reason, code=139):
    """Terminate the entire process immediately (like a segfault / OOM kill)."""
    log(f"*** FATAL FAULT: {reason} -> process terminating NOW ***")
    sys.stdout.flush()
    os._exit(code)  # skips atexit/finally: a genuine hard crash


# ------------------------------------------------------------------ heartbeat sender
def heartbeat_loop(boot_id, interval, secure, monitor_addr):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq = 0
    next_t = time.monotonic()
    while True:
        seq += 1
        try:
            sock.sendto(common.make_heartbeat(common.SERVICE_NAME, boot_id, seq, secure),
                        monitor_addr)
        except OSError as e:
            log(f"heartbeat send error: {e}")  # keep trying; the monitor may be restarting
        next_t += interval                       # fixed-rate schedule, no drift
        time.sleep(max(0.0, next_t - time.monotonic()))


# ------------------------------------------------------------------ fault injector
def fault_injector(mean_seconds):
    """Randomly kills the process after an exponentially distributed delay."""
    while True:
        time.sleep(random.expovariate(1.0 / mean_seconds))
        crash("background fault injector fired (simulated OOM/segfault)")


# ------------------------------------------------------------------ request handling
def handle_request(data, state, args):
    state["requests"] += 1
    state["leak"] += random.randint(1, 4)       # simulated memory leak (units arbitrary)

    try:
        text = data.decode("utf-8")
        parts = text.strip().split(" ")
        well_formed = len(parts) == 3 and parts[0] == "AUTH"
    except UnicodeDecodeError:
        text, parts, well_formed = "", [], False

    # --- stochastic crash triggers ---
    p = args.crash_prob + state["leak"] * args.leak_factor       # grows as the "leak" grows
    if not well_formed:
        p = max(p, args.malformed_crash_prob)                    # bad input is riskier
    if random.random() < p:
        crash(f"unhandled error while processing request #{state['requests']} "
              f"(p={p:.3f}, leak={state['leak']}, well_formed={well_formed})")

    if not well_formed:
        return b"ERROR malformed request"
    _, user, pw = parts
    if USERS.get(user) == pw:
        token = hmac.new(TICKET_KEY, f"{user}|{time.time()}".encode(), hashlib.sha256).hexdigest()[:24]
        return f"TICKET {token}".encode()
    return b"DENIED"


def main():
    ap = argparse.ArgumentParser(description="Critical auth/ticket service with random crashes")
    ap.add_argument("--secure", action="store_true", help="send HMAC-authenticated heartbeats")
    ap.add_argument("--interval", type=float, default=common.T_INTERVAL, help="heartbeat period T (s)")
    ap.add_argument("--crash-prob", type=float, default=0.01, help="base per-request crash prob")
    ap.add_argument("--leak-factor", type=float, default=0.0002, help="extra crash prob per leak unit")
    ap.add_argument("--malformed-crash-prob", type=float, default=0.30,
                    help="crash prob on malformed input")
    ap.add_argument("--inject-mean", type=float, default=30.0,
                    help="mean seconds until background fault injection (0 = disabled)")
    ap.add_argument("--no-crash", action="store_true", help="disable all crashes (for testing)")
    args = ap.parse_args()

    boot_id = uuid.uuid4().hex[:8]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(common.SERVICE_ADDR)
    log(f"started boot_id={boot_id} listening on {common.SERVICE_ADDR}, "
        f"heartbeat T={args.interval}s -> {common.MONITOR_ADDR} secure={args.secure}")

    threading.Thread(target=heartbeat_loop, daemon=True,
                     args=(boot_id, args.interval, args.secure, common.MONITOR_ADDR)).start()
    if not args.no_crash and args.inject_mean > 0:
        threading.Thread(target=fault_injector, daemon=True, args=(args.inject_mean,)).start()
    if args.no_crash:
        args.crash_prob = args.malformed_crash_prob = args.leak_factor = 0.0

    state = {"requests": 0, "leak": 0}
    while True:
        try:
            data, addr = sock.recvfrom(2048)
        except OSError:
            continue
        reply = handle_request(data, state, args)
        try:
            sock.sendto(reply, addr)
        except OSError:
            pass


if __name__ == "__main__":
    main()
