@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Run Setup-SADD.cmd first.
  exit /b 1
)
echo Downloading the official verified runtime and Qwen model. This needs internet once.
".venv\Scripts\python.exe" scripts/setup_local_ai.py
if errorlevel 1 (
  pause
  exit /b 1
)
".venv\Scripts\python.exe" scripts/start_local_ai.py
if errorlevel 1 pause
