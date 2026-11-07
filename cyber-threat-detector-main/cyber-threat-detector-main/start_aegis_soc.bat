@echo off
title AEGIS Cyber Threat Defense Command - SOC Engine
cd /d "%~dp0"
echo =========================================================================
echo   AEGIS CYBER THREAT DETECTOR - REAL-TIME HIGH-LEVEL BACKEND SYSTEM
echo =========================================================================

if exist .venv\Scripts\python.exe (
    set "PYTHON_EXE=.venv\Scripts\python.exe"
) else (
    set "PYTHON_EXE=python"
)

echo [*] Launching AEGIS Real-Time SOC Portal...
echo [*] Open in browser at: http://localhost:8000
"%PYTHON_EXE%" run_backend.py
pause
