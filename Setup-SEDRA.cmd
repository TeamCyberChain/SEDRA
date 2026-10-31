@echo off
setlocal
cd /d "%~dp0"
py -3.12 --version
if errorlevel 1 (
  echo Install Python 3.12 from python.org, then run this setup again.
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" py -3.12 -m venv .venv
if exist "offline_wheels\numpy-2.3.5-cp312-cp312-win_amd64.whl" (
  ".venv\Scripts\python.exe" -m pip install --no-index --find-links offline_wheels -r requirements.txt
) else (
  ".venv\Scripts\python.exe" -m pip install --only-binary=:all: -r requirements.txt
)
if errorlevel 1 (
  echo Installation failed. Preserve the error above for investigation.
  pause
  exit /b 1
)
echo Setup complete. Run Start-SEDRA.cmd.
pause
