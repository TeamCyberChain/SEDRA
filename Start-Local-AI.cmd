@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Run Setup-SADD.cmd first.
  exit /b 1
)
".venv\Scripts\python.exe" scripts/start_local_ai.py
if errorlevel 1 pause
