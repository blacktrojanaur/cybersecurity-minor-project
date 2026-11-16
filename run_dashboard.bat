@echo off
cd /d "%~dp0"
echo =================================================================
echo   STARTING ZERO TRUST SECURITY PLATFORM DASHBOARD (LOCAL)
echo =================================================================
echo.
echo [*] Opening dashboard in your default browser...
start http://localhost:5000
echo.
echo [*] Starting local HTTP server on port 5000...
echo     Press Ctrl+C to stop the server at any time.
echo.
python -m http.server 5000 --bind 127.0.0.1 --directory dashboard/static
pause
