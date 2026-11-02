"""
ha_common.py - shared pieces for Part 2 (cluster layout, wire helpers, control-channel framing).

Cluster layout (all on localhost):
    node A : service UDP 9001, control UDP 9101
    node B : service UDP 9002, control UDP 9102
    monitor: heartbeat UDP 9000 (same as Part 1)
Clients know both service endpoints (stand-in for a floating/virtual IP) and use whichever
node currently answers as PRIMARY. The standby answers "ERR NOT_PRIMARY".

Control channel (monitor -> node): JSON envelopes {"body": {...}, "mac": "..."}.
  BASELINE: no mac. SECURE (--secure): HMAC-SHA256 + freshness window on every message and reply.
"""
import hashlib
import hmac
import json
import os
import socket
import time

import common  # Part 1: SHARED_SECRET, FRESHNESS_WINDOW, SERVICE_NAME, heartbeat format

HOST = "127.0.0.1"
NODES = {
    "A": {"service": (HOST, 9001), "control": (HOST, 9101)},
    "B": {"service": (HOST, 9002), "control": (HOST, 9102)},
}
CKPT_DIR = "checkpoints"
CKPT_FILE = os.path.join(CKPT_DIR, "state.json")
RUN_DIR = "run"                      # pid files (node_A.pid / node_B.pid)

# username -> (password, role)   (dummy credential store)
USERS = {"alice": ("wonderland", "user"), "bob": ("builder", "user"), "carol": ("hunter2", "admin")}
MAX_FAILS = 3                        # failed logins before an account name is blocklisted


def other(node_id):
    return "B" if node_id == "A" else "A"


def stamp():
    t = time.time()
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) + f".{int((t % 1) * 1000):03d}"


# ------------------------------------------------------------------ service-reply helpers
def reply_suffix(node, role, epoch):
    return f" @node={node},role={role},epoch={epoch}"


def split_reply(text):
    """'TICKET abc user @node=A,role=PRIMARY,epoch=1' -> ('TICKET abc user', {'node':'A',...})"""
    if " @" not in text:
        return text, {}
    body, _, tail = text.rpartition(" @")
    meta = {}
    for kv in tail.split(","):
        if "=" in kv:
            k, v = kv.split("=", 1)
            meta[k] = v
    if "epoch" in meta:
        try:
            meta["epoch"] = int(meta["epoch"])
        except ValueError:
            meta["epoch"] = -1
    return body, meta


def parse_kv(body):
    """'STATUS tickets=2 locked=a,b' -> {'tickets':'2','locked':'a,b'}"""
    out = {}
    for tok in body.split(" ")[1:]:
        if "=" in tok:
            k, v = tok.split("=", 1)
            out[k] = v
    return out


def udp_query(addr, text, timeout=0.6):
    """One request/one reply over a fresh socket. Returns (body, meta) or (None, None)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(text.encode() if isinstance(text, str) else text, addr)
        data, _ = s.recvfrom(4096)
    except (socket.timeout, OSError):
        return None, None
    finally:
        s.close()
    return split_reply(data.decode("utf-8", "replace"))


# ------------------------------------------------------------------ control channel framing
def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def mac_of(obj):
    return hmac.new(common.SHARED_SECRET, canon(obj), hashlib.sha256).hexdigest()


def seal(body, secure):
    body = dict(body)
    body["ts"] = time.time()
    body["nonce"] = os.urandom(4).hex()
    env = {"body": body}
    if secure:
        env["mac"] = mac_of(body)
    return json.dumps(env).encode()


def unseal(data, secure):
    """Parse a control message/reply. Raises ValueError if malformed / forged / stale."""
    try:
        env = json.loads(data.decode("utf-8"))
        body = env["body"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, AttributeError):
        raise ValueError("malformed control message")
    if not isinstance(body, dict):
        raise ValueError("malformed control body")
    if secure:
        if not hmac.compare_digest(str(env.get("mac", "")), mac_of(body)):
            raise ValueError("bad/missing HMAC")
        ts = body.get("ts")
        if not isinstance(ts, (int, float)) or abs(time.time() - ts) > common.FRESHNESS_WINDOW:
            raise ValueError("stale control message (replay?)")
    return body


def ctl_call(node_id, cmd, epoch, secure, timeout=0.6):
    """Send a control command to a node; returns the reply body dict or None."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(seal({"cmd": cmd, "epoch": epoch}, secure), NODES[node_id]["control"])
        data, _ = s.recvfrom(4096)
        return unseal(data, secure)
    except (socket.timeout, OSError, ValueError):
        return None
    finally:
        s.close()
