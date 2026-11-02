#!/usr/bin/env python3
"""
failover_monitor.py - UPDATED MONITOR + FAILOVER CONTROLLER (Part 2).

Everything from Part 1 (push heartbeat, T / N / W = N*T timeout) plus automatic recovery:

  heartbeats stop for W  ->  [CRASH DETECTED]
                         ->  [FAILOVER TRIGGERED]  (PROMOTE sent to the standby's control port)
                         ->  [SERVICE RESTORED]    (standby verified answering as PRIMARY)

All three lines are timestamped, printed, and appended to failover_incidents.log.

BASELINE mode: promotes the standby as soon as heartbeats stop. If the heartbeats were merely
               delayed/dropped while the primary is alive, this creates TWO primaries (split-brain).
--secure mode: authenticated control channel + heartbeat checks, plus
                 * second opinion: PING the "dead" primary over the control channel first; if it still
                   answers, ABORT the failover (heartbeat path is degraded, node is alive)
                 * stale-primary fencing: a valid heartbeat from a node that is no longer the primary
                   triggers a FENCE (epoch-based step-down) so only one primary survives.
"""
import argparse
import socket
import time

import common
import ha_common as ha

LOG_FILE = "failover_incidents.log"


class FailoverMonitor:
    def __init__(self, args):
        self.a = args
        self.secure = args.secure
        self.window = args.interval * args.missed
        self.primary = None            # node id currently watched as primary
        self.epoch = 0
        self.state = "WAITING"         # WAITING | HEALTHY | SUSPECT | RETRY
        self.last_valid = None         # monotonic time of last accepted primary heartbeat
        self.last_boot = None
        self.last_seq = -1
        self.beats = 0
        self.next_retry = 0.0
        self.last_fence = 0.0

    def emit(self, level, text, to_file=False):
        line = f"[{ha.stamp()}] [{level}] {text}"
        print(line, flush=True)
        if to_file:
            try:
                with open(LOG_FILE, "a") as f:
                    f.write(line + "\n")
            except OSError:
                pass

    # ---------------------------------------------------------------- heartbeat validation
    def accept(self, data):
        """Return (ok, reason, node_id, msg)."""
        try:
            msg = common.parse_heartbeat(data)
        except ValueError as e:
            return False, str(e), None, None
        node = msg["svc"].split("/", 1)[1] if "/" in msg["svc"] else None
        if node not in ha.NODES:
            return False, f"unknown service name {msg['svc']!r}", None, None
        if self.secure:
            if not common.verify_mac(msg):
                return False, "bad/missing HMAC (forged heartbeat?)", node, None
            skew = abs(time.time() - msg["ts"])
            if skew > common.FRESHNESS_WINDOW:
                return False, f"stale timestamp (skew {skew:.1f}s) - replay?", node, None
            if node == self.primary and msg["boot"] == self.last_boot and msg["seq"] <= self.last_seq:
                return False, f"non-increasing seq {msg['seq']} <= {self.last_seq} - replay?", node, None
        return True, "", node, msg

    # ---------------------------------------------------------------- failover
    def probe_service(self, node, epoch, timeout=2.0):
        """Confirm the promoted node really serves clients as PRIMARY at the new epoch."""
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            _, meta = ha.udp_query(ha.NODES[node]["service"], "STATUS", timeout=0.3)
            if meta and meta.get("role") == "PRIMARY" and meta.get("epoch") == epoch:
                return True
            time.sleep(0.05)
        return False

    def on_timeout(self, now, retry=False):
        old = self.primary
        if not retry:
            self.t_detect = now
            self.emit("CRASH DETECTED",
                      f"no valid heartbeat from node {old} for {now - self.last_valid:.2f}s "
                      f"(> W={self.window:.2f}s = {self.a.missed} missed beats of T={self.a.interval}s)", True)

        if self.secure:                                     # second opinion over a separate channel
            r = ha.ctl_call(old, "PING", self.epoch, True)
            if r and r.get("role") == "PRIMARY":
                if self.state != "SUSPECT":
                    self.emit("FAILOVER ABORTED",
                              f"node {old} still answers PING as PRIMARY (epoch {r.get('epoch')}): heartbeat path is "
                              f"degraded but the node is ALIVE - NOT promoting the standby (avoids split-brain)", True)
                self.state, self.next_retry = "SUSPECT", now + self.window
                return

        target = ha.other(old)
        pr = ha.ctl_call(target, "PING", self.epoch, self.secure)
        if not pr or pr.get("role") != "STANDBY":
            self.emit("FAILOVER FAILED", f"node {target} is not an available STANDBY - retrying in {self.window:.1f}s", True)
            self.state, self.next_retry = "RETRY", now + self.window
            return

        if self.do_promote(target, self.epoch + 1, now):
            return

    def do_promote(self, target, new_epoch, now):
        """PROMOTE `target`, verify it serves clients, log the timeline. Returns True on success."""
        t_trig = time.monotonic()
        self.emit("FAILOVER TRIGGERED", f"promoting node {target} to PRIMARY (epoch {self.epoch} -> {new_epoch})", True)
        r = ha.ctl_call(target, "PROMOTE", new_epoch, self.secure, timeout=self.a.promote_timeout)
        if r and not r.get("ok") and r.get("min_epoch"):          # checkpoint carries a newer epoch: retry once
            new_epoch = r["min_epoch"]
            r = ha.ctl_call(target, "PROMOTE", new_epoch, self.secure, timeout=self.a.promote_timeout)
        if not r or not r.get("ok"):
            self.emit("FAILOVER FAILED", f"promotion of node {target} rejected/failed: {r}", True)
            self.state, self.next_retry = "RETRY", now + self.window
            return False
        if not self.probe_service(target, new_epoch):
            self.emit("FAILOVER FAILED", f"node {target} promoted but not answering clients", True)
            self.state, self.next_retry = "RETRY", now + self.window
            return False

        t_done = time.monotonic()
        self.emit("SERVICE RESTORED",
                  f"node {target} is PRIMARY (epoch {new_epoch}) | state: {r.get('tickets')} tickets from "
                  f"{r.get('ckpt')} checkpoint, degraded={r.get('degraded')} | "
                  f"detect->restored {1000 * (t_done - self.t_detect):.0f} ms, "
                  f"failover-trigger->restored {1000 * (t_done - t_trig):.0f} ms, "
                  f"last-heartbeat->restored {1000 * (t_done - self.last_valid):.0f} ms", True)
        self.primary, self.epoch, self.state = target, new_epoch, "HEALTHY"
        self.last_valid, self.last_boot, self.last_seq = time.monotonic(), None, -1
        return True

    def bootstrap(self, now):
        """No primary was ever seen (it may have died before its first heartbeat): adopt or elect one."""
        seen = {}
        for n in ha.NODES:
            r = ha.ctl_call(n, "PING", 0, self.secure)
            if r:
                seen[n] = r
        prim = sorted((r.get("epoch", 0), n) for n, r in seen.items() if r.get("role") == "PRIMARY")
        if prim:
            epoch, n = prim[-1]
            self.primary, self.epoch, self.state, self.last_valid = n, epoch, "HEALTHY", now
            self.emit("INFO", f"adopted running node {n} as PRIMARY (epoch {epoch})")
            return
        standby = sorted(n for n, r in seen.items() if r.get("role") == "STANDBY")
        if not standby:
            self.emit("INFO", "no cluster nodes reachable yet - still waiting")
            return
        self.t_detect, self.last_valid = time.monotonic(), now
        self.epoch = max([r.get("epoch", 0) for r in seen.values()] + [0])
        self.emit("CRASH DETECTED", "cluster has no PRIMARY and no heartbeats were ever received "
                                    "(primary died before its first heartbeat?)", True)
        self.primary = ha.other(standby[0])               # pretend the missing node was primary
        if not self.do_promote(standby[0], self.epoch + 1, now):
            self.primary, self.state = None, "WAITING"       # try the election again later

    # ---------------------------------------------------------------- main loop
    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((ha.HOST, self.a.hb_port))
        sock.settimeout(self.a.interval / 5)
        self.next_bootstrap = time.monotonic() + max(3.0, 2 * self.window)
        self.emit("INFO", f"failover monitor up on {ha.HOST}:{self.a.hb_port} | mode={'SECURE' if self.secure else 'BASELINE'} "
                          f"| T={self.a.interval}s N={self.a.missed} W={self.window:.2f}s")
        while True:
            try:
                try:
                    data, addr = sock.recvfrom(4096)
                except (socket.timeout, OSError):
                    data = None
                now = time.monotonic()

                if data is not None:
                    ok, why, node, msg = self.accept(data)
                    if not ok:
                        if self.secure:
                            self.emit("REJECT", f"dropped datagram from {addr[0]}:{addr[1]}: {why}", True)
                    elif self.primary is None:                       # first valid beat: learn who is primary
                        pr = ha.ctl_call(node, "PING", 0, self.secure)
                        self.primary, self.epoch = node, (pr or {}).get("epoch", 1)
                        self.emit("INFO", f"watching node {node} as PRIMARY (epoch {self.epoch})")
                    if ok and node == self.primary:
                        if msg["boot"] != self.last_boot:
                            self.emit("INFO", f"primary instance node {node} boot={msg['boot']}")
                            self.last_boot, self.last_seq = msg["boot"], msg["seq"]
                        else:
                            self.last_seq = max(self.last_seq, msg["seq"])
                        if self.state == "SUSPECT":
                            self.emit("INFO", f"heartbeats from node {node} resumed - no failover was needed", True)
                        self.state, self.last_valid, self.beats = "HEALTHY", now, self.beats + 1
                        if not self.a.quiet:
                            self.emit("OK", f"valid heartbeat #{self.beats} from node {node} (seq={self.last_seq})")
                    elif ok and node != self.primary and self.secure and time.time() - self.last_fence > 3:
                        self.last_fence = time.time()
                        self.emit("SPLIT-BRAIN DETECTED",
                                  f"authentic heartbeat from node {node}, which is NOT the current primary "
                                  f"({self.primary}, epoch {self.epoch}) -> sending FENCE", True)
                        ha.ctl_call(node, "FENCE", self.epoch, True)
                    # BASELINE: beats from a non-primary node are silently ignored (naive controller)

                if self.state == "WAITING" and now >= self.next_bootstrap:
                    self.next_bootstrap = now + self.window
                    self.bootstrap(now)
                elif self.state == "HEALTHY" and now - self.last_valid > self.window:
                    self.on_timeout(now)
                elif self.state in ("SUSPECT", "RETRY") and now >= self.next_retry:
                    self.on_timeout(now, retry=True)
            except Exception as e:                                   # the monitor must never die
                self.emit("WARN", f"internal error ignored: {type(e).__name__}: {e}")


def main():
    ap = argparse.ArgumentParser(description="Heartbeat monitor + automatic failover controller")
    ap.add_argument("--secure", action="store_true")
    ap.add_argument("--interval", type=float, default=common.T_INTERVAL, help="expected heartbeat period T (s)")
    ap.add_argument("--missed", type=int, default=common.MISSED_N, help="N missed beats => failure")
    ap.add_argument("--hb-port", type=int, default=common.MONITOR_ADDR[1], help="UDP port to listen for heartbeats")
    ap.add_argument("--promote-timeout", type=float, default=3.0)
    ap.add_argument("--quiet", action="store_true", help="don't print every valid heartbeat")
    args = ap.parse_args()
    try:
        FailoverMonitor(args).run()
    except KeyboardInterrupt:
        print("\nfailover monitor stopped.")


if __name__ == "__main__":
    main()
