@echo off
setlocal EnableExtensions EnableDelayedExpansion
rem SenseTrust live demo for Windows. Double-click this file.
rem It finds (or installs) Python, installs the dependencies once, starts the
rem mutual-TLS gateway and opens the dashboard in your browser.
cd /d "%~dp0"
title SenseTrust live demo

echo.
echo  SenseTrust live demo
echo  ====================
echo.

rem ---- 1. Find a Python the dependencies support (3.10 - 3.13, 3.12 preferred) ----
set "PY="
for %%V in (3.12 3.11 3.13 3.10) do (
  if not defined PY (
    py -%%V -c "import sys" >nul 2>nul && set "PY=py -%%V"
  )
)
if not defined PY (
  for %%P in ("%LOCALAPPDATA%\Programs\Python\Python312\python.exe" "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" "%ProgramFiles%\Python312\python.exe" "%ProgramFiles%\Python311\python.exe") do (
    if not defined PY if exist %%P set "PY=%%~P"
  )
)
if not defined PY (
  python -c "import sys; sys.exit(0 if (3,10) <= sys.version_info[:2] <= (3,13) else 1)" >nul 2>nul && set "PY=python"
)
if not defined PY (
  echo [1/4] No suitable Python found. Installing Python 3.12 with winget...
  echo       Accept any prompts that appear.
  winget install -e --id Python.Python.3.12 --scope user --accept-package-agreements --accept-source-agreements
  if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
)
if not defined PY (
  echo.
  echo  Could not find or install Python automatically.
  echo  Install Python 3.12 from https://www.python.org/downloads/release/python-3120/
  echo  tick "Add python.exe to PATH", then double-click this file again.
  goto :fail
)
echo [1/4] Using Python:
if "%PY:~0,3%"=="py " (%PY% --version) else ("%PY%" --version)

rem ---- 2. Virtual environment and dependencies (first run only) ----
if exist venv\Scripts\python.exe (
  venv\Scripts\python -c "import sys; sys.exit(0 if (3,10) <= sys.version_info[:2] <= (3,13) else 1)" >nul 2>nul || (
    echo [2/4] Existing venv uses an unsupported Python - rebuilding it...
    rmdir /s /q venv
  )
)
if not exist venv\Scripts\python.exe (
  echo [2/4] Creating virtual environment...
  if "%PY:~0,3%"=="py " (%PY% -m venv venv) else ("%PY%" -m venv venv)
  if not exist venv\Scripts\python.exe goto :fail
)
if not exist venv\.deps-installed (
  echo [2/4] Installing dependencies - first run only, takes a few minutes...
  venv\Scripts\python -m pip install --disable-pip-version-check -q --upgrade pip
  venv\Scripts\python -m pip install --disable-pip-version-check --prefer-binary -r requirements.txt
  if errorlevel 1 (
    echo.
    echo  Installing dependencies failed - see the messages above.
    echo  Deleting the venv so the next run starts clean.
    rmdir /s /q venv
    goto :fail
  )
  echo ok> venv\.deps-installed
) else (
  echo [2/4] Dependencies already installed.
)

rem ---- 3. Pick free ports (an earlier run may still be open) ----
set "UI_PORT="
for %%N in (8501 8502 8503 8504 8505) do (
  if not defined UI_PORT (
    netstat -ano | findstr /r /c:":%%N .*LISTENING" >nul || set "UI_PORT=%%N"
  )
)
if not defined UI_PORT set "UI_PORT=8510"
set "GW_PORT=8443"
netstat -ano | findstr /r /c:":8443 .*LISTENING" >nul && set "GW_PORT=8444"

echo [3/4] Starting the mutual-TLS gateway on https://127.0.0.1:!GW_PORT! (second window)...
start "SenseTrust gateway" venv\Scripts\python -m sensetrust.server --data data --port !GW_PORT!

echo [4/4] Starting the dashboard on http://localhost:!UI_PORT! ...
echo.
echo  Your browser opens in a few seconds. If it does not, open
echo      http://localhost:!UI_PORT!
echo  Keep this window open while you use the demo. Close it to stop.
echo.
start "" cmd /c "timeout /t 10 /nobreak >nul & start http://localhost:!UI_PORT!"
venv\Scripts\python -m streamlit run dashboard\app.py --server.headless true --server.port !UI_PORT! --browser.gatherUsageStats false --client.toolbarMode minimal
echo.
echo  The dashboard stopped.

:fail
echo.
echo  If something went wrong, copy all the text in this window and send it over.
pause
exit /b 1
