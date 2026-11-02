#!/usr/bin/env python3
"""
node.py - one cluster node (Part 2). Runs as PRIMARY or warm STANDBY (passive redundancy).

PRIMARY : serves AUTH / VERIFY / STATUS requests, keeps dynamic state (tickets, failed-login
          counters, blocklist), checkpoints it to disk, sends heartbeats to the monitor, and
          can crash at random (same stochastic triggers as Part 1).
STANDBY : process is up ("warm") and answers control PINGs, but serves nothing
          ("ERR NOT_PRIMARY") and sends no heartbeats. When the monitor sends PROMOTE it loads
          the latest valid checkpoint, adopts the new epoch and becomes PRIMARY.

Service protocol (UDP text):  AUTH <user> <password> | VERIFY <token> | STATUS
Every reply carries a suffix " @node=A,role=PRIMARY,epoch=1".
Control protocol (monitor -> node, UDP JSON): PING | PROMOTE <epoch> | FENCE <epoch>
Epoch = fencing token: a node never accepts PROMOTE/FENCE with an epoch <= its own.
"""
import argparse
import copy
import os
import random
import socket
import threading
import time
import uuid

import checkpoint
import common
import ha_common as ha


class Node:
    def __init__(self, args):
        self.a = args
        self.id = args.id
        self.secure = args.secure
        self.lock = threading.RLock()
        self.save_lock = threading.Lock()       # one checkpoint write at a time
        self.role = "PRIMARY" if args.role == "primary" else "STANDBY"
        self.epoch = 1 if self.role == "PRIMARY" else 0
        self.state = checkpoint.new_state()
        self.dirty = False
        self.degraded = False
        self.ckpt_source = "none"
        self.leak = 0
        self.boot = uuid.uuid4().hex[:8]
        self.hb_seq = 0
        self.last_save = 0.0

        # NOTE: no SO_REUSEADDR - a second process can't silently share a node's port.
        self.svc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.svc.bind(ha.NODES[self.id]["service"])
        self.ctl = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ctl.bind(ha.NODES[self.id]["control"])

        os.makedirs(ha.RUN_DIR, exist_ok=True)
        with open(os.path.join(ha.RUN_DIR, f"node_{self.id}.pid"), "w") as f:
            f.write(str(os.getpid()))

        if self.role == "PRIMARY":             # initial primary starts clean
            for p in (ha.CKPT_FILE, ha.CKPT_FILE + ".prev", ha.CKPT_FILE + ".tmp"):
                try:
                    os.remove(p)
                except OSError:
                    pass
            self.save_now()

    # ---------------------------------------------------------------- helpers
    def log(self, msg):
        print(f"[{ha.stamp()}] [node {self.id} pid={os.getpid()} {self.role} e{self.epoch}] {msg}", flush=True)

    def suffix(self):
        return ha.reply_suffix(self.id, self.role, self.epoch).encode()

    def crash(self, reason):
        self.log(f"*** FATAL FAULT: {reason} -> process terminating NOW ***")
        os._exit(139)                          # hard crash: no cleanup, whole process dies

    def save_now(self):
        with self.lock:
            snap = copy.deepcopy(self.state)
            epoch = self.epoch
            self.dirty = False
        try:
            with self.save_lock:
                checkpoint.save(ha.CKPT_FILE, snap, epoch, self.secure)
            self.last_save = time.monotonic()
        except OSError as e:
            self.log(f"checkpoint write FAILED: {e}")
            self.dirty = True

    def mutated(self):
        self.dirty = True
        if self.a.ckpt_interval <= 0:          # write-through mode: no window of lost updates
            self.save_now()

    # ---------------------------------------------------------------- service requests
    def handle(self, data):
        with self.lock:
            if self.role != "PRIMARY":
                return b"ERR NOT_PRIMARY" + self.suffix()
        try:
            parts = data.decode("utf-8").strip().split(" ")
        except UnicodeDecodeError:
            parts = []
        cmd = parts[0] if parts else ""

        if cmd == "STATUS" and len(parts) == 1:        # monitoring query: exempt from crash triggers
            with self.lock:
                st = self.state
                return (f"STATUS tickets={len(st['tickets'])} locked={','.join(sorted(st['locked'])) or '-'} "
                        f"requests={st['requests']} degraded={self.degraded} ckpt={self.ckpt_source}"
                        ).encode() + self.suffix()

        well_formed = (cmd == "AUTH" and len(parts) == 3) or (cmd == "VERIFY" and len(parts) == 2)

        # ---- stochastic crash triggers (never a fixed request count) ----
        with self.lock:
            self.leak += random.randint(1, 4)          # simulated memory leak
            p = self.a.crash_prob + self.leak * self.a.leak_factor
            if not well_formed:
                p = max(p, self.a.malformed_crash_prob)
        if random.random() < p:
            self.crash(f"unhandled error on request (p={p:.3f}, leak={self.leak}, well_formed={well_formed})")

        if not well_formed:
            return b"ERROR malformed request" + self.suffix()

        with self.lock:
            st = self.state
            if cmd == "AUTH":
                _, user, pw = parts
                st["requests"] += 1
                if user in st["locked"]:
                    body = "LOCKED"
                elif user in ha.USERS and ha.USERS[user][0] == pw:
                    token = os.urandom(12).hex()
                    role = ha.USERS[user][1]
                    st["tickets"][token] = {"user": user, "role": role, "issued": time.time()}
                    st["failed"][user] = 0
                    body = f"TICKET {token} {role}"
                else:
                    st["failed"][user] = st["failed"].get(user, 0) + 1
                    if st["failed"][user] >= ha.MAX_FAILS and user not in st["locked"]:
                        st["locked"].append(user)      # blocklist entry - must survive a crash
                    body = "DENIED"
                self.mutated()
            else:                                      # VERIFY
                t = st["tickets"].get(parts[1])
                body = f"VALID {t['user']} {t['role']}" if t else "INVALID"
            return body.encode() + self.suffix()

    # ---------------------------------------------------------------- failover (control channel)
    def promote(self, epoch):
        with self.lock:
            if self.role == "PRIMARY":
                return {"ok": False, "err": "already PRIMARY", "role": self.role, "epoch": self.epoch}
            if epoch <= self.epoch:
                return {"ok": False, "err": f"stale epoch {epoch} <= {self.epoch}", "role": self.role, "epoch": self.epoch}
            state, ck_epoch, source, warns = checkpoint.load(ha.CKPT_FILE, self.secure)
            for w in warns:
                self.log(f"WARNING: {w}")
            if source != "none" and epoch <= ck_epoch:
                return {"ok": False, "err": f"stale epoch {epoch} <= checkpoint epoch {ck_epoch}",
                        "role": self.role, "epoch": self.epoch, "min_epoch": ck_epoch + 1}
            if state is None:
                state, self.degraded = checkpoint.new_state(), True
                self.log("ALERT: NO VALID CHECKPOINT - starting with EMPTY state (all tickets/blocklist lost)")
            else:
                self.degraded = False
            self.state, self.ckpt_source = state, source
            self.epoch, self.role = epoch, "PRIMARY"
            self.boot, self.hb_seq, self.leak = uuid.uuid4().hex[:8], 0, 0
            self.log(f"PROMOTED to PRIMARY (epoch {epoch}); loaded {source} checkpoint with "
                     f"{len(self.state['tickets'])} tickets, locked={self.state['locked']}")
        self.save_now()                                # also heals a tampered/corrupt file on disk
        return {"ok": True, "node": self.id, "role": "PRIMARY", "epoch": epoch,
                "tickets": len(self.state["tickets"]), "ckpt": source, "degraded": self.degraded}

    def fence(self, epoch):
        with self.lock:
            if self.role != "PRIMARY":
                return {"ok": True, "note": "not primary, nothing to fence", "role": self.role}
            if epoch <= self.epoch:
                return {"ok": False, "err": f"stale epoch {epoch} <= {self.epoch}", "role": self.role}
            self.log(f"FENCED by controller (epoch {epoch} > {self.epoch}): stepping down and exiting")
        threading.Timer(0.2, lambda: os._exit(0)).start()   # supervisor restarts us as STANDBY
        return {"ok": True, "role": "FENCED", "epoch": epoch}

    def control_loop(self):
        while True:
            try:
                data, addr = self.ctl.recvfrom(4096)
            except OSError:
                continue
            try:
                msg = ha.unseal(data, self.secure)
                cmd, epoch = msg.get("cmd"), msg.get("epoch")
                if not isinstance(epoch, int):
                    raise ValueError("bad epoch")
            except ValueError as e:
                self.log(f"[control] REJECTED message from {addr[0]}:{addr[1]}: {e}")
                continue
            if cmd == "PING":
                with self.lock:
                    reply = {"ok": True, "node": self.id, "role": self.role, "epoch": self.epoch}
            elif cmd == "PROMOTE":
                reply = self.promote(epoch)
            elif cmd == "FENCE":
                reply = self.fence(epoch)
            else:
                reply = {"ok": False, "err": "unknown command"}
            try:
                self.ctl.sendto(ha.seal(reply, self.secure), addr)
            except OSError:
                pass

    # ---------------------------------------------------------------- background threads
    def heartbeat_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        next_t = time.monotonic()
        while True:
            with self.lock:
                if self.role == "PRIMARY":
                    self.hb_seq += 1
                    pkt = common.make_heartbeat(f"{common.SERVICE_NAME}/{self.id}", self.boot,
                                                self.hb_seq, self.secure)
                else:
                    pkt = None
            if pkt:
                try:
                    sock.sendto(pkt, (ha.HOST, self.a.hb_port))
                except OSError:
                    pass
            next_t += self.a.interval
            time.sleep(max(0.0, next_t - time.monotonic()))

    def checkpoint_loop(self):
        while True:
            time.sleep(0.05)
            with self.lock:                    # periodic snapshot every interval (even if idle)
                due = (self.role == "PRIMARY" and self.a.ckpt_interval > 0
                       and time.monotonic() - self.last_save >= self.a.ckpt_interval)
            if due:
                self.save_now()

    def fault_injector(self):
        while True:
            time.sleep(random.expovariate(1.0 / self.a.inject_mean))
            with self.lock:
                is_primary = self.role == "PRIMARY"
            if is_primary:
                self.crash("background fault injector fired (simulated OOM/segfault)")

    # ---------------------------------------------------------------- main loop
    def run(self):
        self.log(f"started boot={self.boot} service={ha.NODES[self.id]['service']} control={ha.NODES[self.id]['control']} "
                 f"hb->{ha.HOST}:{self.a.hb_port} T={self.a.interval}s ckpt_interval={self.a.ckpt_interval}s "
                 f"secure={self.secure}")
        for fn in (self.control_loop, self.heartbeat_loop, self.checkpoint_loop):
            threading.Thread(target=fn, daemon=True).start()
        if not self.a.no_crash and self.a.inject_mean > 0:
            threading.Thread(target=self.fault_injector, daemon=True).start()
        if self.a.no_crash:
            self.a.crash_prob = self.a.malformed_crash_prob = self.a.leak_factor = 0.0
        while True:
            try:
                data, addr = self.svc.recvfrom(2048)
            except OSError:
                continue
            reply = self.handle(data)
            try:
                self.svc.sendto(reply, addr)
            except OSError:
                pass


def main():
    ap = argparse.ArgumentParser(description="Cluster node: primary or warm standby")
    ap.add_argument("--id", required=True, choices=["A", "B"])
    ap.add_argument("--role", choices=["primary", "standby"], default="standby")
    ap.add_argument("--secure", action="store_true", help="HMAC heartbeats, control msgs and checkpoints")
    ap.add_argument("--hb-port", type=int, default=common.MONITOR_ADDR[1],
                    help="where heartbeats go (9000 = monitor; 9050 = audit relay)")
    ap.add_argument("--interval", type=float, default=common.T_INTERVAL, help="heartbeat period T (s)")
    ap.add_argument("--ckpt-interval", type=float, default=1.0,
                    help="seconds between checkpoints (0 = write-through after every change)")
    ap.add_argument("--crash-prob", type=float, default=0.01)
    ap.add_argument("--leak-factor", type=float, default=0.0002)
    ap.add_argument("--malformed-crash-prob", type=float, default=0.30)
    ap.add_argument("--inject-mean", type=float, default=30.0,
                    help="mean seconds until random background crash while PRIMARY (0 = disabled)")
    ap.add_argument("--no-crash", action="store_true", help="disable all crashes (testing)")
    args = ap.parse_args()
    try:
        Node(args).run()
    except OSError as e:
        print(f"[node {args.id}] cannot start (is another copy still running on these ports?): {e}")
        raise SystemExit(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
