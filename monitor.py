#!/usr/bin/env python3
"""
monitor.py - independent HEARTBEAT MONITOR (separate process, separate socket).

Pattern : PUSH heartbeat (service -> monitor UDP datagram every T seconds).
Logic   : each valid beat resets a deadline. If N consecutive periods (window W = N*T)
          pass with no valid beat, the monitor declares the service FAILED, prints a
          timestamped alert, and appends the incident to the log file.
Safety  : the monitor never crashes on bad input or when the service dies; every datagram
          is parsed defensively, and the main loop catches socket errors.

BASELINE mode (default) accepts any well-formed HEARTBEAT (intentionally weak, for Task 5).
--secure mode additionally requires: valid HMAC, fresh timestamp, increasing seq per boot id.
"""
import argparse
import socket
import time

import common

LOG_FILE = "monitor_incidents.log"


def stamp():
    t = time.time()
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) + f".{int((t % 1) * 1000):03d}"


class Monitor:
    def __init__(self, args):
        self.args = args
        self.window = args.interval * args.missed
        self.state = "WAITING"           # WAITING -> HEALTHY -> FAILED -> HEALTHY ...
        self.last_valid = None           # monotonic time of last accepted beat
        self.last_boot = None
        self.last_seq = -1
        self.beats = 0
        self.rejected = 0
        self.fail_started = None
        self.incident_wall = None

    # ---- output ----
    def emit(self, level, text, to_file=False):
        line = f"[{stamp()}] [{level}] {text}"
        print(line, flush=True)
        if to_file:
            try:
                with open(LOG_FILE, "a") as f:
                    f.write(line + "\n")
            except OSError as e:
                print(f"[{stamp()}] [WARN] could not write log file: {e}", flush=True)

    # ---- heartbeat validation ----
    def accept(self, data, addr):
        """Return (ok, reason)."""
        try:
            msg = common.parse_heartbeat(data)
        except ValueError as e:
            return False, str(e)
        if self.args.secure:
            if not common.verify_mac(msg):
                return False, "bad/missing HMAC (forged heartbeat?)"
            skew = abs(time.time() - msg["ts"])
            if skew > common.FRESHNESS_WINDOW:
                return False, f"stale timestamp (skew {skew:.1f}s > {common.FRESHNESS_WINDOW}s) - replay?"
            if msg["boot"] == self.last_boot and msg["seq"] <= self.last_seq:
                return False, f"non-increasing seq {msg['seq']} <= {self.last_seq} - replay?"
        # accepted: update replay-tracking state
        if msg["boot"] != self.last_boot:
            self.last_boot, self.last_seq = msg["boot"], msg["seq"]
            self.emit("INFO", f"new service instance boot_id={msg['boot']} from {addr[0]}:{addr[1]}")
        else:
            self.last_seq = max(self.last_seq, msg["seq"])
        return True, ""

    # ---- main loop ----
    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(common.MONITOR_ADDR)
        sock.settimeout(self.args.interval / 5)       # poll tick for the deadline check
        self.emit("INFO", f"monitor up on {common.MONITOR_ADDR} | mode={'SECURE' if self.args.secure else 'BASELINE'} "
                          f"| T={self.args.interval}s N={self.args.missed} W={self.window:.2f}s")
        wiretap = open(self.args.wiretap, "a") if self.args.wiretap else None

        while True:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                data = None
            except OSError:                    # e.g. ICMP-induced errors on some platforms
                data = None

            now = time.monotonic()
            if data is not None:
                if wiretap:                    # simulates an on-path capture (tcpdump/Wireshark)
                    wiretap.write(data.decode("utf-8", "replace").replace("\n", " ") + "\n")
                    wiretap.flush()
                ok, why = self.accept(data, addr)
                if ok:
                    self.last_valid = now
                    self.beats += 1
                    if self.state == "FAILED":
                        down = now - self.fail_started
                        self.emit("RECOVERED", f"service heartbeats resumed after ~{down:.2f}s of declared downtime",
                                  to_file=True)
                    if self.state != "HEALTHY":
                        self.state = "HEALTHY"
                    if not self.args.quiet:
                        self.emit("OK", f"valid heartbeat #{self.beats} (boot={self.last_boot} seq={self.last_seq}) from {addr[0]}:{addr[1]}")
                else:
                    self.rejected += 1
                    self.emit("REJECT", f"dropped datagram from {addr[0]}:{addr[1]}: {why}", to_file=True)

            # ---- fault detection ----
            if self.state == "HEALTHY" and self.last_valid is not None and now - self.last_valid > self.window:
                self.state = "FAILED"
                self.fail_started = self.last_valid
                self.emit("ALERT", f"SERVICE FAILURE DETECTED: no valid heartbeat for {now - self.last_valid:.2f}s "
                                   f"(> W={self.window:.2f}s = {self.args.missed} missed beats of T={self.args.interval}s). "
                                   f"Last valid: boot={self.last_boot} seq={self.last_seq}", to_file=True)


def main():
    ap = argparse.ArgumentParser(description="Heartbeat monitor (push model)")
    ap.add_argument("--secure", action="store_true", help="require HMAC + freshness + increasing seq")
    ap.add_argument("--interval", type=float, default=common.T_INTERVAL, help="expected period T (s)")
    ap.add_argument("--missed", type=int, default=common.MISSED_N, help="N missed beats => failure")
    ap.add_argument("--quiet", action="store_true", help="don't print every valid beat")
    ap.add_argument("--wiretap", metavar="FILE", help="append raw datagrams to FILE (simulated packet capture)")
    args = ap.parse_args()
    try:
        Monitor(args).run()
    except KeyboardInterrupt:
        print("\nmonitor stopped.")


if __name__ == "__main__":
    main()
