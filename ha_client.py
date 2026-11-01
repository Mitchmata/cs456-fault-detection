#!/usr/bin/env python3
"""
ha_client.py - cluster-aware client.

Knows both service endpoints (stand-in for a floating IP). It tries the endpoint that last
worked, skips replies of "ERR NOT_PRIMARY", and falls over to the other node on timeout.

  python3 ha_client.py auth alice wonderland
  python3 ha_client.py verify <token>
  python3 ha_client.py status
  python3 ha_client.py demo            # continuous workload: issue tickets, re-verify old ones,
                                       # report outages and any LOST state after a failover
"""
import argparse
import random
import time

import ha_common as ha

CREDS = [("alice", "wonderland"), ("bob", "builder"), ("carol", "hunter2")]


class HAClient:
    def __init__(self, timeout=0.4):
        self.names = ["A", "B"]
        self.pref = 0
        self.timeout = timeout

    def request(self, text):
        """Returns (body, meta) from the current primary, or (None, None) if no primary answers."""
        for i in (self.pref, 1 - self.pref):
            body, meta = ha.udp_query(ha.NODES[self.names[i]]["service"], text, self.timeout)
            if body is None or body.startswith("ERR NOT_PRIMARY"):
                continue
            self.pref = i
            return body, meta
        return None, None


def demo(args):
    c = HAClient()
    tickets = []                       # (token, user, issued_at)
    outage_start = None
    last_crash = None
    last_node = None
    n = 0
    print(f"[client] demo workload at ~{args.rate} req/s (Ctrl-C to stop)")
    while True:
        n += 1
        r = random.random()
        if r < 0.45 or not tickets:
            u, p = random.choice(CREDS)
            text, kind = f"AUTH {u} {p}", "AUTH"
        elif r < 0.9:
            tok, u, _ = random.choice(tickets)
            text, kind = f"VERIFY {tok}", "VERIFY"
        else:
            text, kind = "AUTH mallory wrong-password", "BADAUTH"

        body, meta = c.request(text)
        now = time.time()
        if body is None:
            if outage_start is None:
                outage_start = last_crash = now
                print(f"[{ha.stamp()}] [client] !! no PRIMARY reachable - outage began", flush=True)
        else:
            if outage_start is not None:
                print(f"[{ha.stamp()}] [client] >> service back after {now - outage_start:.2f}s outage "
                      f"(now served by node {meta.get('node')}, epoch {meta.get('epoch')})", flush=True)
                outage_start = None
            if meta.get("node") != last_node:
                print(f"[{ha.stamp()}] [client] serving node is now {meta.get('node')} (epoch {meta.get('epoch')})", flush=True)
                last_node = meta.get("node")
            if kind == "AUTH" and body.startswith("TICKET"):
                tickets.append((body.split(" ")[1], text.split(" ")[1], now))
                tickets = tickets[-40:]
            flag = ""
            if kind == "VERIFY" and body == "INVALID":
                tok = text.split(" ")[1]
                issued = next(t[2] for t in tickets if t[0] == tok)
                before = (last_crash - issued) if last_crash else None
                tickets = [t for t in tickets if t[0] != tok]
                if before is not None and before < args.ckpt_window:
                    flag = (f"   <-- ticket lost: issued {before:.1f}s BEFORE the crash, i.e. newer than the last "
                            f"checkpoint (expected loss window of passive redundancy)")
                else:
                    flag = "   <-- !! UNEXPECTED STATE LOSS (ticket was old enough to be in a checkpoint)"
            shown = text if kind != "VERIFY" else f"VERIFY {text.split(' ')[1][:8]}.."
            shown_body = body if not body.startswith("TICKET") else f"TICKET {body.split(' ')[1][:8]}.. {body.split(' ')[2]}"
            print(f"[{ha.stamp()}] [client] node {meta.get('node')} e{meta.get('epoch')}: {shown} -> {shown_body}{flag}", flush=True)
        time.sleep(1.0 / args.rate)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("auth"); a.add_argument("user"); a.add_argument("password")
    v = sub.add_parser("verify"); v.add_argument("token")
    sub.add_parser("status")
    d = sub.add_parser("demo"); d.add_argument("--rate", type=float, default=3.0)
    d.add_argument("--ckpt-window", type=float, default=1.6, help="seconds before a crash within which loss is expected")
    args = ap.parse_args()
    if args.cmd == "demo":
        try:
            demo(args)
        except KeyboardInterrupt:
            pass
        return
    text = {"auth": lambda: f"AUTH {args.user} {args.password}", "verify": lambda: f"VERIFY {args.token}",
            "status": lambda: "STATUS"}[args.cmd]()
    body, meta = HAClient().request(text)
    print(f"{body}   (served by node {meta.get('node')}, epoch {meta.get('epoch')})" if body else "no PRIMARY reachable")


if __name__ == "__main__":
    main()
