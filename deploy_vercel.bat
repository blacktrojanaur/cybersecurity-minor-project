@echo off
cd /d "%~dp0"
echo =================================================================
echo   DEPLOYING ZERO TRUST SECURITY PLATFORM TO VERCEL
echo =================================================================
echo.

echo [*] Checking for Node.js / npx...
where npx >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
  echo [!] npx (Node.js) is not detected on your PATH.
  echo.
  echo To deploy to Vercel without Node.js installed locally:
  echo   1. Push your code to GitHub using push_to_github.bat
  echo   2. Go to https://vercel.com and log in with GitHub
  echo   3. Click "Add New..." -^> "Project"
  echo   4. Select "cybersecurity-minor-project" and click "Deploy"
  echo.
  pause
  exit /b
)

echo [*] Deploying directly to Vercel via CLI...
echo     (If this is your first time, Vercel will ask you to log in via browser)
echo.
call npx vercel --prod

echo.
echo =================================================================
echo   Deployment completed!
echo =================================================================
pause

