@echo off
cd /d "%~dp0"
echo Starting CipherTwin Backend and Frontend...
start "CipherTwin Backend" cmd /k "call \"%~dp0start_backend.bat\""
start "CipherTwin Frontend" cmd /k "call \"%~dp0start_frontend.bat\""
