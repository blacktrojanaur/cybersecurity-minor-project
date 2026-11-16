@echo off
cd /d "%~dp0"
echo =================================================================
echo   LAUNCHING FULL ZERO TRUST MICROSERVICES CLUSTER
echo =================================================================
echo.
python run_local.py
pause

