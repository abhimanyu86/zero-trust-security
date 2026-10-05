#!/usr/bin/env bash
# SenseTrust live demo. Opens http://localhost:8501
set -e
cd "$(dirname "$0")"
PY=${PYTHON:-python3}
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || {
  echo "Python 3.10 or newer is needed."; exit 1; }
[ -x venv/bin/python ] || "$PY" -m venv venv
if [ ! -f venv/.deps-installed ]; then
  echo "Installing dependencies (first run only)..."
  venv/bin/python -m pip install -q --upgrade pip
  venv/bin/python -m pip install -q -r requirements.txt
  touch venv/.deps-installed
fi
echo "Starting the mutual-TLS gateway on https://127.0.0.1:8443 ..."
venv/bin/python -m sensetrust.server --data data &
GW=$!
trap 'kill $GW 2>/dev/null' EXIT
echo "Starting the dashboard on http://localhost:8501 ..."
( sleep 6; { command -v xdg-open && xdg-open http://localhost:8501; } || { command -v open && open http://localhost:8501; } ) >/dev/null 2>&1 &
venv/bin/python -m streamlit run dashboard/app.py --server.headless true --server.port 8501 --browser.gatherUsageStats false --client.toolbarMode minimal
