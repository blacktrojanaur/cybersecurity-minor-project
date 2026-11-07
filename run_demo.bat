@echo off
title ZTSP Turnkey Demo Runner
echo ==========================================================
echo   AI-Augmented Zero Trust Security Orchestration Platform
echo   Turnkey Demo Launcher
echo ==========================================================
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_demo.ps1"

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] An error occurred during execution.
    pause
)

