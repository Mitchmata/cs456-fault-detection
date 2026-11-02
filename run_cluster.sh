#!/usr/bin/env bash
# Starts the whole cluster in ONE terminal: node A (primary), node B (standby) and the failover
# monitor. Crashed nodes are restarted automatically as STANDBY (like a process supervisor), so the
# cluster can survive several crashes in a row.
#
#   ./run_cluster.sh                 baseline (intentionally vulnerable) cluster
#   ./run_cluster.sh --secure        hardened cluster
#   ./run_cluster.sh --relay         nodes send heartbeats via the audit relay (:9050) for attack 1
#   ./run_cluster.sh --inject 10     mean seconds until a random background crash (default 20)
#   (flags combine, e.g.  ./run_cluster.sh --secure --relay)
# Node logs: logs/node_A.log, logs/node_B.log      Monitor output: this terminal
SECURE=""; HB=""; INJ="--inject-mean 20"
while [ $# -gt 0 ]; do
  case "$1" in
    --secure) SECURE="--secure" ;;
    --relay)  HB="--hb-port 9050" ;;
    --inject) INJ="--inject-mean $2"; shift ;;
  esac
  shift
done
PY=python3; command -v python3 >/dev/null 2>&1 || PY=python
mkdir -p logs; rm -rf checkpoints run
trap 'kill 0' EXIT INT TERM

node_loop() {            # $1 = node id, $2 = first role
  role=$2
  while true; do
    $PY node.py --id "$1" --role "$role" $SECURE $HB $INJ >> "logs/node_$1.log" 2>&1
    echo "[supervisor] node $1 exited with code $? - restarting as standby" >> "logs/node_$1.log"
    role=standby; sleep 2
  done
}
node_loop A primary &
node_loop B standby &
sleep 1
$PY failover_monitor.py $SECURE
