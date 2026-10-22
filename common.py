"""
common.py - shared constants and heartbeat wire format.

Wire format (one UDP datagram, JSON):
    {"type": "HEARTBEAT", "svc": "auth-ticket", "boot": "<random id per process start>",
     "seq": 42, "ts": 1760000000.123, "mac": "<hex HMAC-SHA256>"}   # "mac" only in --secure mode

BASELINE mode (default): no authentication, no freshness checks -> deliberately
vulnerable so the adversarial script can demonstrate spoofing and replay.

SECURE mode (--secure on service AND monitor): HMAC over the fields with a shared secret,
per-boot monotonically increasing sequence numbers, and a timestamp freshness window.
"""
import hashlib
import hmac
import json
import os
import time

# ---- Network defaults (all loopback; change for a multi-host demo) ----
MONITOR_ADDR = ("127.0.0.1", 9000)   # monitor listens here for heartbeats
SERVICE_ADDR = ("127.0.0.1", 9001)   # service listens here for client requests
SERVICE_NAME = "auth-ticket"

# ---- Heartbeat timing (justify these in your PDF report) ----
T_INTERVAL = 0.5        # T: seconds between heartbeats
MISSED_N = 3            # N: consecutive missed beats before declaring failure
# Timeout window W = N * T = 1.5 s  (worst-case MTTD ~ W + one monitor poll tick)

# Demo-only shared secret for --secure mode. In real life, load from a KMS / env var.
SHARED_SECRET = os.environ.get("HB_SECRET", "cs456-demo-secret").encode()
FRESHNESS_WINDOW = 2.0  # seconds a timestamp may differ from monitor clock (secure mode)


def _mac_input(svc, boot, seq, ts):
    return f"{svc}|{boot}|{seq}|{ts:.6f}".encode()


def make_heartbeat(svc, boot, seq, secure=False):
    """Build a heartbeat datagram (bytes)."""
    ts = time.time()
    msg = {"type": "HEARTBEAT", "svc": svc, "boot": boot, "seq": seq, "ts": ts}
    if secure:
        msg["mac"] = hmac.new(SHARED_SECRET, _mac_input(svc, boot, seq, ts),
                              hashlib.sha256).hexdigest()
    return json.dumps(msg).encode()


def parse_heartbeat(data):
    """Parse and structurally validate a datagram. Returns dict or raises ValueError."""
    try:
        msg = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError(f"malformed datagram: {e}")
    if not isinstance(msg, dict) or msg.get("type") != "HEARTBEAT":
        raise ValueError("not a HEARTBEAT message")
    if not isinstance(msg.get("svc"), str) or not isinstance(msg.get("boot"), str):
        raise ValueError("bad svc/boot fields")
    if not isinstance(msg.get("seq"), int) or isinstance(msg.get("seq"), bool):
        raise ValueError("bad seq field")
    if not isinstance(msg.get("ts"), (int, float)) or isinstance(msg.get("ts"), bool):
        raise ValueError("bad ts field")
    return msg


def verify_mac(msg):
    """Constant-time HMAC check (secure mode)."""
    mac = msg.get("mac")
    if not isinstance(mac, str):
        return False
    expected = hmac.new(SHARED_SECRET,
                        _mac_input(msg["svc"], msg["boot"], msg["seq"], msg["ts"]),
                        hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, expected)
