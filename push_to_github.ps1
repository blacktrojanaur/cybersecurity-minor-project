# PowerShell GitHub Push Script for ZTSP
Set-Location $PSScriptRoot

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  PUSHING ZERO TRUST SECURITY PLATFORM TO GITHUB" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[*] Staging all files..." -ForegroundColor Yellow
git add .

Write-Host "[*] Committing changes..." -ForegroundColor Yellow
git commit -m "feat: complete working Zero Trust platform with interactive GitHub Pages live demo"

Write-Host "[*] Setting branch to main..." -ForegroundColor Yellow
git branch -M main

Write-Host "[*] Pushing to origin main..." -ForegroundColor Yellow
git push -u origin main

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "=================================================================" -ForegroundColor Green
    Write-Host "  SUCCESSFULLY PUSHED TO GITHUB!" -ForegroundColor Green
    Write-Host "=================================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "To enable your live GitHub Pages site:" -ForegroundColor Cyan
    Write-Host "  1. Open https://github.com/blacktrojanaur/cybersecurity-minor-project/settings/pages"
    Write-Host "  2. Under 'Build and deployment' -> 'Source': Select 'Deploy from a branch'"
    Write-Host "  3. Select branch: 'main' and folder: '/docs', then click Save."
    Write-Host ""
    Write-Host "  Your live dashboard will be hosted at:" -ForegroundColor Green
    Write-Host "  https://blacktrojanaur.github.io/cybersecurity-minor-project/" -ForegroundColor Green
    Write-Host "=================================================================" -ForegroundColor Green
} else {
    Write-Host "[!] Git push failed. Please verify your internet connection or git credentials." -ForegroundColor Red
}

