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
  echo To host on Vercel:
  echo   1. Visit https://vercel.com/new and log in with GitHub
  echo   2. Import "cybersecurity-minor-project"
  echo   3. Click "Deploy" (vercel.json automatically configures everything!)
  echo.
  echo To host on GitHub Pages:
  echo   1. Open https://github.com/blacktrojanaur/cybersecurity-minor-project/settings/pages
  echo   2. Set Source: "Deploy from a branch", Branch: "main", Folder: "/docs", click Save.
  echo =================================================================
) else (
  echo [!] Push encountered an issue. Please review the output above.
  echo     If prompted for credentials, make sure you are logged into GitHub.
)

echo.
pause

