@echo off
setlocal
cd /d "%~dp0frontend"

if not exist node_modules (
    echo Installing frontend dependencies...
    call npm ci
)

echo Starting CipherTwin Frontend (Vite)...
call npm run dev -- --host 0.0.0.0 --port 5173
endlocal
