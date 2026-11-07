# AEGIS Cyber Threat Defense Command - PowerShell Launcher
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

Write-Host "=========================================================================" -ForegroundColor Cyan
Write-Host "  AEGIS CYBER THREAT DETECTOR - REAL-TIME HIGH-LEVEL BACKEND SYSTEM" -ForegroundColor Yellow
Write-Host "=========================================================================" -ForegroundColor Cyan

$PythonExe = Join-Path $ScriptDir ".venv\Scripts\python.exe"
if (-not (Test-Path $PythonExe)) {
    $PythonExe = "python"
}

Write-Host "[*] Executing backend SOC server via: $PythonExe" -ForegroundColor Green
& $PythonExe run_backend.py
