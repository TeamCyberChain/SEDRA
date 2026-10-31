@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Run Setup-SEDRA.cmd first. Python 3.12 is required.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -c "import sys; sys.exit(0 if sys.version_info[:2] == (3,12) else 1)"
if errorlevel 1 (
  echo This environment is not Python 3.12. Use Setup-SEDRA.cmd.
  pause
  exit /b 1
)
echo Open http://127.0.0.1:8765/ in your browser.
if exist "data\local_ai\runtime\llama-server.exe" (
  ".venv\Scripts\python.exe" scripts/start_local_ai.py
  if not errorlevel 1 set "SEDRA_AI_PROVIDER=local"
)
".venv\Scripts\python.exe" scripts/check_running.py
if not errorlevel 1 (
  echo SEDRA is already running. Opening the workbench.
  start "" "http://127.0.0.1:8765/"
  exit /b 0
)
echo Keep this window open during the demonstration. Ctrl+C stops the server.
".venv\Scripts\python.exe" -m sedra.app --port 8765 --data-dir data/runtime-sedra
if errorlevel 1 pause
