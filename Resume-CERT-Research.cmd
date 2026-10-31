@echo off
setlocal
cd /d "%~dp0"
echo This resumes the optional official CERT download and frozen v2 experiment.
echo The local demo does not require this download. Research status appears in the app.
".venv\Scripts\python.exe" -u scripts/run_research.py
if errorlevel 1 pause
