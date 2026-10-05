@echo off
rem SenseTrust live demo - double-click to run. Opens http://localhost:8501
cd /d "%~dp0"

where py >nul 2>nul && (set PY=py -3) || (set PY=python)
%PY% -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul
if errorlevel 1 (
  echo Python 3.10 or newer is needed. Install it from https://www.python.org/downloads/
  echo and tick "Add python.exe to PATH" during setup, then run this file again.
  pause
  exit /b 1
)

echo Using:
%PY% --version

if not exist venv\Scripts\python.exe (
  echo Creating virtual environment...
  %PY% -m venv venv || (pause & exit /b 1)
)
if not exist venv\.deps-installed (
  echo Installing dependencies, first run only - this takes a few minutes...
  venv\Scripts\python -m pip install --upgrade pip >nul
  venv\Scripts\python -m pip install -r requirements.txt || (pause & exit /b 1)
  echo done> venv\.deps-installed
)

echo Starting the mutual-TLS gateway on https://127.0.0.1:8443 in a second window...
start "SenseTrust gateway" venv\Scripts\python -m sensetrust.server --data data

echo Starting the dashboard on http://localhost:8501 ...
echo Your browser opens in a few seconds. Keep this window open while you use the demo.
start "" cmd /c "timeout /t 8 /nobreak >nul & start http://localhost:8501"
venv\Scripts\python -m streamlit run dashboard\app.py --server.headless true --server.port 8501 --browser.gatherUsageStats false --client.toolbarMode minimal
echo.
echo The dashboard stopped. If you saw an error above, copy it and send it over.
pause
