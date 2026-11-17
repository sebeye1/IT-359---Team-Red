@echo off
rem One-step launcher for Windows: on first use it creates a virtual environment (.venv) and
rem installs the requirements, then runs WebRecon. Everything after run.bat is passed to main.py:
rem     run.bat                        guided walkthrough
rem     run.bat https://example.com    scan a site
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo [setup] Creating a virtual environment in .venv ^(first run only^)...
    py -3 -m venv .venv 2>nul || python -m venv .venv
    if not exist ".venv\Scripts\python.exe" (
        echo [!] Could not create a virtual environment. Install Python 3.9 or newer from python.org and try again.
        exit /b 1
    )
)

if not exist ".venv\.installed" (
    echo [setup] Installing requirements...
    ".venv\Scripts\python.exe" -m pip install --quiet -r requirements.txt
    if errorlevel 1 exit /b 1
    echo done> ".venv\.installed"
)

".venv\Scripts\python.exe" main.py %*
exit /b %errorlevel%
