#!/usr/bin/env python3
"""
audit_failover.py - ADVERSARIAL AUDIT for Part 2 (run from the project folder, localhost lab only).

Attack Scenario 1 - false-failover : act as a lossy/malicious network between the nodes and the
    monitor. Heartbeats are forwarded for a while, then DROPPED while the primary is still alive.
    Does the system promote the standby anyway and end up with two concurrent primaries (split-brain)?
    Needs the nodes started with  --hb-port 9050  so their heartbeats pass through this relay.

Attack Scenario 2 - tamper-checkpoint : attacker with filesystem access kills the primary and, in the
    window before failover completes, modifies the checkpoint file.
      --mode inject        add a forged ADMIN ticket + clear the blocklist, then recompute the (unkeyed) sha256
      --mode corrupt       truncate/garble the current checkpoint
      --mode corrupt-both  garble the current AND the previous checkpoint
    Then checks what the promoted standby believes.

  python3 audit_failover.py false-failover --duration 8
  python3 audit_failover.py tamper-checkpoint --mode inject
"""
import argparse
import hashlib
import json
import os
import signal
import socket
import sys
import threading
import time

import ha_common as ha

FORGED_TOKEN = "deadbeef" * 3          # 24 hex chars, never issued by the service


def say(msg):
    print(f"[{ha.stamp()}] [auditor] {msg}", flush=True)


def roles():
    """{'A': (role, epoch, body) | None, 'B': ...} by asking each node's service port."""
    out = {}
    for n in ("A", "B"):
        body, meta = ha.udp_query(ha.NODES[n]["service"], "STATUS", 0.5)
        out[n] = None if body is None else (meta.get("role"), meta.get("epoch"), body)
    return out


def show_roles(prefix=""):
    r = roles()
    for n in ("A", "B"):
        say(f"{prefix}node {n}: " + ("NO RESPONSE (down / fenced / exited)" if r[n] is None
                                      else f"role={r[n][0]} epoch={r[n][1]}"))
    return r


def current_primary():
    for n, v in roles().items():
        if v and v[0] == "PRIMARY":
            return n
    return None


# =========================================================================== scenario 1
def false_failover(args):
    relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    relay.bind((ha.HOST, args.relay_port))
    relay.settimeout(0.2)
    out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    st = {"forward": True, "seen": 0, "dropped": 0, "stop": False}

    def loop():
        while not st["stop"]:
            try:
                data, _ = relay.recvfrom(4096)
            except (socket.timeout, OSError):
                continue
            st["seen"] += 1
            if st["forward"]:
                out.sendto(data, (ha.HOST, args.monitor_port))
            else:
                st["dropped"] += 1
    threading.Thread(target=loop, daemon=True).start()

    say(f"relay listening on :{args.relay_port}, forwarding to monitor :{args.monitor_port}")
    time.sleep(3)
    if st["seen"] == 0:
        sys.exit("[auditor] no heartbeats arrived at the relay. Start the nodes with --hb-port "
                 f"{args.relay_port} (e.g. ./run_cluster.sh --relay) and try again.")
    say(f"relay has seen {st['seen']} heartbeats; network is healthy")
    primary = current_primary()
    if not primary:
        sys.exit("[auditor] no PRIMARY found")
    say(f"primary is node {primary}; writing legitimate state to it first")
    body, _ = ha.udp_query(ha.NODES[primary]["service"], "AUTH alice wonderland")
    t0 = body.split(" ")[1] if body and body.startswith("TICKET") else None
    time.sleep(1.5)                                         # let a checkpoint land

    say(f">>> ATTACK: dropping ALL heartbeats for {args.duration}s (primary {primary} stays alive and keeps serving)")
    st["forward"] = False
    start = time.time()
    split = False
    while time.time() - start < args.duration:
        r = roles()
        if all(r[n] and r[n][0] == "PRIMARY" for n in ("A", "B")):
            split = True
            break
        time.sleep(0.5)

    if split:
        say("!!! SPLIT-BRAIN CONFIRMED: both nodes report role=PRIMARY at the same time")
        show_roles("   ")
        a_body, _ = ha.udp_query(ha.NODES["A"]["service"], "AUTH alice wonderland")
        b_body, _ = ha.udp_query(ha.NODES["B"]["service"], "AUTH bob builder")
        tA = a_body.split(" ")[1] if a_body and a_body.startswith("TICKET") else None
        tB = b_body.split(" ")[1] if b_body and b_body.startswith("TICKET") else None
        say("clients hitting different 'primaries' now get conflicting state:")
        if tA and tB:
            ab, _ = ha.udp_query(ha.NODES["B"]["service"], f"VERIFY {tA}")
            ba, _ = ha.udp_query(ha.NODES["A"]["service"], f"VERIFY {tB}")
            say(f"   ticket issued by A, verified at B -> {ab}")
            say(f"   ticket issued by B, verified at A -> {ba}")
        if t0:
            say("   pre-attack ticket verifies at A -> " + str(ha.udp_query(ha.NODES['A']['service'], f'VERIFY {t0}')[0])
                + " | at B -> " + str(ha.udp_query(ha.NODES['B']['service'], f'VERIFY {t0}')[0]))
    else:
        say(f"no second primary appeared within {args.duration}s")
        show_roles("   ")

    say(f">>> network restored: forwarding heartbeats again; waiting {args.heal_wait}s to see how the system reacts")
    st["forward"] = True
    time.sleep(args.heal_wait)
    final = show_roles("final: ")
    both = all(final[n] and final[n][0] == "PRIMARY" for n in ("A", "B"))
    print()
    say("=== VERDICT (scenario 1: induced false failover) ===")
    if split and both:
        say("VULNERABLE: the monitor promoted a standby while the primary was alive, and the two primaries "
            "STILL coexist after the network healed (no fencing). State diverges between them.")
    elif split:
        say("PARTIALLY HANDLED: split-brain occurred but was resolved afterwards (the stale primary was fenced).")
    else:
        say("RESISTANT: no split-brain. The controller did not promote a second primary while the first was alive.")
    st["stop"] = True


# =========================================================================== scenario 2
def tamper_checkpoint(args):
    primary = current_primary()
    if not primary:
        sys.exit("[auditor] no PRIMARY found - start the cluster first")
    standby = ha.other(primary)
    say(f"primary is node {primary}, standby is node {standby}")

    body, _ = ha.udp_query(ha.NODES[primary]["service"], "AUTH alice wonderland")
    t0 = body.split(" ")[1] if body and body.startswith("TICKET") else None
    for _ in range(ha.MAX_FAILS):
        ha.udp_query(ha.NODES[primary]["service"], "AUTH mallory wrong")
    say(f"seeded legitimate state: alice's ticket {t0[:8] if t0 else None}.. and 'mallory' on the blocklist")
    say(f"waiting {args.settle}s so the primary checkpoints that state to disk")
    time.sleep(args.settle)

    pid_file = os.path.join(ha.RUN_DIR, f"node_{primary}.pid")
    try:
        pid = int(open(pid_file).read().strip())
    except (OSError, ValueError):
        sys.exit(f"[auditor] cannot read {pid_file} (run this from the project folder)")
    say(f">>> ATTACK step 1: killing primary node {primary} (pid {pid}) so it cannot overwrite my edit")
    os.kill(pid, getattr(signal, "SIGKILL", signal.SIGTERM))

    cur, prev = ha.CKPT_FILE, ha.CKPT_FILE + ".prev"
    say(f">>> ATTACK step 2: tampering with {cur} (mode={args.mode}) before the standby loads it")
    try:
        if args.mode == "inject":
            env = json.load(open(cur))
            st = env["payload"]["state"]
            st["tickets"][FORGED_TOKEN] = {"user": "mallory", "role": "admin", "issued": time.time()}
            st["locked"] = []
            st["failed"] = {}
            env["sha256"] = hashlib.sha256(ha.canon(env["payload"])).hexdigest()   # attacker recomputes unkeyed hash
            json.dump(env, open(cur, "w"))
            say("injected forged ADMIN ticket for 'mallory', cleared the blocklist, recomputed sha256 (cannot forge the HMAC)")
        else:
            for p in ([cur] if args.mode == "corrupt" else [cur, prev]):
                raw = open(p, "rb").read()
                open(p, "wb").write(raw[: len(raw) // 2] + b"\x00GARBAGE\xff")
            say("garbled " + ("the current checkpoint" if args.mode == "corrupt" else "both current and previous checkpoints"))
    except (OSError, KeyError, json.JSONDecodeError) as e:
        sys.exit(f"[auditor] tamper failed: {e}")

    say(f"waiting for the monitor to fail over to node {standby} (up to {args.wait}s) ...")
    t_start = time.time()
    while time.time() - t_start < args.wait:
        body, meta = ha.udp_query(ha.NODES[standby]["service"], "STATUS", 0.4)
        if meta and meta.get("role") == "PRIMARY":
            break
        time.sleep(0.3)
    else:
        sys.exit("[auditor] standby never became PRIMARY (failover did not happen)")
    say(f"node {standby} is PRIMARY again after {time.time() - t_start:.1f}s")

    forged, _ = ha.udp_query(ha.NODES[standby]["service"], f"VERIFY {FORGED_TOKEN}")
    legit, _ = ha.udp_query(ha.NODES[standby]["service"], f"VERIFY {t0}") if t0 else (None, None)
    status, _ = ha.udp_query(ha.NODES[standby]["service"], "STATUS")
    kv = ha.parse_kv(status or "")
    say(f"VERIFY forged admin ticket   -> {forged}")
    say(f"VERIFY alice's real ticket   -> {legit}")
    say(f"service state after failover -> {status}")

    print()
    say(f"=== VERDICT (scenario 2: tampered checkpoint, mode={args.mode}) ===")
    if args.mode == "inject":
        if forged and forged.startswith("VALID"):
            say("VULNERABLE: the standby trusted the tampered checkpoint -> attacker holds a valid ADMIN session"
                + (" and the blocklist was wiped." if kv.get("locked") == "-" else "."))
        else:
            say(f"BLOCKED: forged state rejected (HMAC check). Recovered from the {kv.get('ckpt')} checkpoint; "
                f"alice's ticket {'survived' if legit and legit.startswith('VALID') else 'was lost'}.")
    else:
        if kv.get("degraded") == "True":
            say("STATE LOST: no valid checkpoint remained, so the standby started EMPTY (fail-closed for tickets, but the "
                "brute-force blocklist was also lost). Availability preserved, state integrity not.")
        else:
            say(f"HANDLED GRACEFULLY: corruption detected, standby fell back to the {kv.get('ckpt')} checkpoint; "
                f"alice's ticket {'survived' if legit and legit.startswith('VALID') else 'was lost (newer than the fallback copy)'}.")


def main():
    ap = argparse.ArgumentParser(description="Part 2 adversarial audit (false failover / tampered checkpoint)")
    sub = ap.add_subparsers(dest="mode_cmd", required=True)
    f = sub.add_parser("false-failover")
    f.add_argument("--duration", type=float, default=8.0, help="seconds to drop heartbeats")
    f.add_argument("--heal-wait", type=float, default=6.0)
    f.add_argument("--relay-port", type=int, default=9050)
    f.add_argument("--monitor-port", type=int, default=9000)
    t = sub.add_parser("tamper-checkpoint")
    t.add_argument("--mode", choices=["inject", "corrupt", "corrupt-both"], default="inject")
    t.add_argument("--settle", type=float, default=2.5)
    t.add_argument("--wait", type=float, default=25.0)
    args = ap.parse_args()
    try:
        (false_failover if args.mode_cmd == "false-failover" else tamper_checkpoint)(args)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
