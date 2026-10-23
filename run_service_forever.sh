#!/usr/bin/env bash
# Restarts the service every time it crashes, so a demo shows repeated crash -> detect -> recover.
# Usage: ./run_service_forever.sh [extra service.py flags, e.g. --secure]
while true; do
  python3 service.py "$@"
  echo "[supervisor] service exited with code $? - restarting in 3s (monitor should have alerted)"
  sleep 3
done
