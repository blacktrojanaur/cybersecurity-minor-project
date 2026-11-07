@echo off
cd /d "%~dp0"
echo =================================================================
echo   PUSHING ZERO TRUST SECURITY PLATFORM TO GITHUB
echo =================================================================
echo.

echo [*] Checking git status...
git status
echo.

echo [*] Staging all files...
git add .
echo.

echo [*] Committing changes...
git commit -m "feat: complete working Zero Trust platform with interactive GitHub Pages live demo"
echo.

echo [*] Ensuring main branch...
git branch -M main
echo.

echo [*] Pushing to remote repository...
git push -u origin main
echo.

if %ERRORLEVEL% EQU 0 (
  echo =================================================================
  echo   SUCCESSFULLY PUSHED TO GITHUB!
  echo =================================================================
  echo.
  echo To view your hosted GitHub Pages site:
  echo   1. Go to your repo on GitHub:
  echo      https://github.com/blacktrojanaur/cybersecurity-minor-project/settings/pages
  echo   2. Under "Build and deployment" -^> "Source":
  echo      Select "Deploy from a branch"
  echo   3. Under "Branch":
  echo      Select "main" and folder "/docs", then click Save.
  echo.
  echo   Your live demo will be published at:
  echo   https://blacktrojanaur.github.io/cybersecurity-minor-project/
  echo =================================================================
) else (
  echo [!] Push encountered an issue. Please review the output above.
  echo     If prompted for credentials, make sure you are logged into GitHub.
)

echo.
pause

