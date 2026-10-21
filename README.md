# CS456 Mini Group Project 1 - Heartbeat Failure Detection

Security domain: **Authentication / Ticket Service** (UDP, dummy credentials).
Failure detection: **push heartbeat** from the service to an independent monitor.
Requires only **Python 3.8+** (standard library, no installs). Everything runs on localhost.

## Files
| File | Role |
|---|---|
| `service.py` | Critical service. Random crash triggers (per-request probability that grows with a simulated leak, plus a random background fault injector). Heartbeat thread is separate from request handling. |
| `monitor.py` | Independent heartbeat monitor. Timeout window W = N x T. Prints timestamped alerts and logs incidents to `monitor_incidents.log`. Never crashes on bad input. |
| `attacker.py` | Adversarial audit: `spoof` (forged heartbeats) and `replay` (captured genuine heartbeat). |
| `client.py` | Traffic generator (valid + malformed AUTH requests) to exercise the per-request crash trigger. |
| `common.py` | Shared constants (T, N, ports, secret) and the heartbeat wire format. |
| `run_service_forever.sh` | Restarts the service after each crash for repeated demos. |

## Setup / run (open each command in its own terminal, inside this folder)

**1. Baseline (intentionally vulnerable) - Terminal 1:**
```bash
python3 monitor.py --wiretap capture.log
```
**Terminal 2:**
```bash
python3 service.py                 # or: ./run_service_forever.sh
```
**Terminal 3 (optional traffic, makes the request-triggered crash fire):**
```bash
python3 client.py --rate 5 --bad-frac 0.1
```
You will see `[OK] valid heartbeat ...` lines, then the service prints `*** FATAL FAULT ***`
and exits, and the monitor prints `[ALERT] SERVICE FAILURE DETECTED` ~1.5 s later.
Useful flags: `service.py --inject-mean 10` (crash sooner on average), `--no-crash` (testing).

**2. Attacks (service already crashed) - Terminal 3:**
```bash
python3 attacker.py spoof                                  # Attack 1: forged heartbeats
python3 attacker.py replay --capture capture.log --delay 0 # Attack 2: replay a genuine packet
```
Baseline result: the monitor logs `RECOVERED` and reports the dead service as healthy -> **attack succeeds**.

**3. Hardened mode (same attacks fail)** - restart monitor and service with `--secure`:
```bash
python3 monitor.py --secure --wiretap capture.log
python3 service.py --secure
python3 attacker.py spoof                                  # -> [REJECT] bad/missing HMAC
python3 attacker.py replay --capture capture.log --delay 3 # -> [REJECT] stale timestamp
```
Secure mode = HMAC-SHA256 (shared secret) + timestamp freshness window (2 s) + increasing sequence
number per boot id. Set a different secret with `export HB_SECRET=...` on both sides.

## Parameters (for the report)
- **Pattern:** push heartbeat. Cheap for the service, one-way, monitor needs no knowledge of the service's address.
- **T = 0.5 s**, **N = 3**, **W = N x T = 1.5 s**.
  Worst-case MTTD is about W plus one poll tick (0.1 s), i.e. roughly 1.6 s.
  N = 3 tolerates two lost/delayed UDP datagrams or a brief scheduling stall before raising a false positive.
  Lower T/N detects faster but risks false alarms; higher values leave the service silently dead longer.
- The heartbeat is emitted from its own thread on a fixed-rate schedule so a busy request handler does not cause false failovers.

## Notes for the adversarial summary
- Baseline accepts any well-formed JSON heartbeat: no authentication, no freshness, no sequence check, so
  both spoofing and byte-for-byte replay keep the monitor "green" while the service is dead.
- `--wiretap` stands in for an on-path capture with tcpdump/Wireshark (loopback traffic can't be sniffed without root).
- Remaining limits of secure mode (good discussion material): shared-secret key management, a replay inside the 2 s window
  of a packet with a not-yet-seen seq (e.g. one the attacker delayed/dropped), clock skew, and DoS flooding of the monitor socket (rate limiting is Part 2 territory).
