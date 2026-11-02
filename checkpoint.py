"""
checkpoint.py - STATE SYNC / CHECKPOINTING module (passive redundancy).

The primary periodically snapshots its dynamic state (issued session tickets, failed-login
counters, blocklist) to a shared file. The standby loads the newest valid snapshot on promotion.

File format  : {"payload": {version, epoch, saved_at, state}, "sha256": ..., "mac": ...}
  sha256     : always present. Catches accidental corruption, but anyone can recompute it,
               so it does NOT stop a deliberate attacker.
  mac        : HMAC-SHA256 with the shared secret, only written/required in --secure mode.
               Stops tampering by someone who can write the file but doesn't know the key.
Safety       : atomic write (temp file + fsync + os.replace) and one previous-good copy
               (state.json.prev) to fall back to when the current file is corrupt or tampered.
"""
import hashlib
import hmac
import json
import os
import shutil
import threading
import time

from ha_common import canon, mac_of


def new_state():
    return {"tickets": {}, "failed": {}, "locked": [], "requests": 0}


def _valid_state(st):
    return (isinstance(st, dict) and isinstance(st.get("tickets"), dict)
            and isinstance(st.get("failed"), dict) and isinstance(st.get("locked"), list)
            and isinstance(st.get("requests"), int))


def _read_verified(path, secure):
    """Return the verified payload dict, or raise ValueError(reason)."""
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except FileNotFoundError:
        raise ValueError("file not found")
    except OSError as e:
        raise ValueError(f"unreadable ({e})")
    try:
        env = json.loads(raw.decode("utf-8"))
        payload = env["payload"]
        if not isinstance(payload, dict):
            raise TypeError
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, AttributeError):
        raise ValueError("not valid JSON / bad envelope (corrupted file)")
    if hashlib.sha256(canon(payload)).hexdigest() != env.get("sha256"):
        raise ValueError("checksum mismatch (corrupted file)")
    if secure and not hmac.compare_digest(str(env.get("mac", "")), mac_of(payload)):
        raise ValueError("HMAC mismatch (checkpoint tampered with or forged)")
    if payload.get("version") != 1 or not isinstance(payload.get("epoch"), int) \
            or not _valid_state(payload.get("state")):
        raise ValueError("unexpected schema")
    return payload


def save(path, state, epoch, secure):
    """Atomically write a checkpoint; keep the previous *valid* one as path + '.prev'."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    payload = {"version": 1, "epoch": epoch, "saved_at": time.time(), "state": state}
    env = {"payload": payload, "sha256": hashlib.sha256(canon(payload)).hexdigest()}
    if secure:
        env["mac"] = mac_of(payload)
    tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
    with open(tmp, "w") as f:
        json.dump(env, f)
        f.flush()
        os.fsync(f.fileno())
    try:                                   # only keep a backup if the current file is itself good
        _read_verified(path, secure)
        shutil.copyfile(path, path + ".prev")
    except ValueError:
        pass
    os.replace(tmp, path)                  # atomic swap


def load(path, secure):
    """
    Try the current checkpoint, then the previous one.
    Returns (state | None, epoch, source, warnings) with source in {'current','previous','none'}.
    """
    warnings = []
    for source, p in (("current", path), ("previous", path + ".prev")):
        try:
            payload = _read_verified(p, secure)
            return payload["state"], payload["epoch"], source, warnings
        except ValueError as e:
            warnings.append(f"{source} checkpoint rejected: {e}")
    return None, 0, "none", warnings
