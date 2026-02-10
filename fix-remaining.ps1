#Requires -RunAsAdministrator
# Fix the 2 remaining items that need admin

# 1. Classic right-click context menu
Write-Host "Setting classic right-click context menu..." -ForegroundColor Cyan
$clsid = "HKCU:\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
New-Item -Path $clsid -Force | Out-Null
Set-ItemProperty -Path $clsid -Name "(Default)" -Value "" -Force
Write-Host "  Done" -ForegroundColor Green

# 2. SystemResponsiveness = 0 (gaming priority)
Write-Host "Setting SystemResponsiveness to 0..." -ForegroundColor Cyan
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Value 0 -Type DWord -Force
Write-Host "  Done" -ForegroundColor Green

# 3. SmartScreen explicit value (belt and suspenders)
Write-Host "Setting SmartScreen explicit Off..." -ForegroundColor Cyan
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Type String -Force
Write-Host "  Done" -ForegroundColor Green

# Restart Explorer for context menu
Write-Host "Restarting Explorer..." -ForegroundColor Cyan
Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Start-Process explorer

Write-Host "`nAll fixed. Right-click your desktop to verify classic menu." -ForegroundColor Green
