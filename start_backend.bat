@echo off
setlocal
cd /d "%~dp0"
set "PYTHONPATH=%~dp0backend"

if exist "%~dp0.venv\Scripts\python.exe" (
    echo Starting CipherTwin Backend using root .venv...
    "%~dp0.venv\Scripts\python.exe" -m uvicorn app.main:app --host 0.0.0.0 --port 8000
) else if exist "%~dp0backend\.venv\Scripts\python.exe" (
    echo Starting CipherTwin Backend using backend\.venv...
    "%~dp0backend\.venv\Scripts\python.exe" -m uvicorn app.main:app --host 0.0.0.0 --port 8000
) else (
    echo Setting up Python virtual environment...
    "C:\Users\LAVANYA\AppData\Local\Programs\Python\Python311\python.exe" -m venv "%~dp0.venv" 2>nul || python -m venv "%~dp0.venv"
    call "%~dp0.venv\Scripts\activate.bat"
    pip install -r "%~dp0backend\requirements.txt"
    "%~dp0.venv\Scripts\python.exe" -m uvicorn app.main:app --host 0.0.0.0 --port 8000
)
endlocal
