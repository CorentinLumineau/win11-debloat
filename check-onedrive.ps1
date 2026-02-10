# Check if OneDrive is still present anywhere

Write-Host "=== OneDrive Status ===" -ForegroundColor Cyan

# 1. Process running?
$proc = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
if ($proc) {
    Write-Host "  [!!] OneDrive process is RUNNING (PID: $($proc.Id))" -ForegroundColor Red
} else {
    Write-Host "  [OK] OneDrive process not running" -ForegroundColor Green
}

# 2. AppxPackage?
$appx = Get-AppxPackage -Name "*OneDrive*" -AllUsers -ErrorAction SilentlyContinue
if ($appx) {
    Write-Host "  [!!] OneDrive AppxPackage found: $($appx.Name)" -ForegroundColor Red
} else {
    Write-Host "  [OK] No OneDrive AppxPackage" -ForegroundColor Green
}

# 3. Provisioned package?
$prov = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object { $_.PackageName -like "*OneDrive*" }
if ($prov) {
    Write-Host "  [!!] OneDrive provisioned package found" -ForegroundColor Red
} else {
    Write-Host "  [OK] No OneDrive provisioned package" -ForegroundColor Green
}

# 4. Setup exe still exists?
$exe64 = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
$exe32 = "$env:SystemRoot\System32\OneDriveSetup.exe"
if (Test-Path $exe64) {
    Write-Host "  [--] OneDriveSetup.exe exists at $exe64 (normal, Windows keeps it)" -ForegroundColor DarkGray
} elseif (Test-Path $exe32) {
    Write-Host "  [--] OneDriveSetup.exe exists at $exe32 (normal, Windows keeps it)" -ForegroundColor DarkGray
} else {
    Write-Host "  [OK] OneDriveSetup.exe not found" -ForegroundColor Green
}

# 5. User folder?
$userFolder = "$env:USERPROFILE\OneDrive"
if (Test-Path $userFolder) {
    $items = (Get-ChildItem $userFolder -Recurse -ErrorAction SilentlyContinue | Measure-Object).Count
    Write-Host "  [--] ~\OneDrive folder still exists ($items items inside)" -ForegroundColor Yellow
} else {
    Write-Host "  [OK] ~\OneDrive folder does not exist" -ForegroundColor Green
}

# 6. Startup entry?
$run = Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "OneDrive" -ErrorAction SilentlyContinue
if ($run) {
    Write-Host "  [!!] OneDrive startup entry found in registry" -ForegroundColor Red
} else {
    Write-Host "  [OK] No OneDrive startup entry" -ForegroundColor Green
}

# 7. Scheduled tasks?
$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like "*OneDrive*" }
if ($tasks) {
    foreach ($t in $tasks) {
        Write-Host "  [!!] OneDrive scheduled task: $($t.TaskName) ($($t.State))" -ForegroundColor Red
    }
} else {
    Write-Host "  [OK] No OneDrive scheduled tasks" -ForegroundColor Green
}

# 8. Policy to prevent reinstall?
$policy = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -ErrorAction SilentlyContinue
if ($policy -and $policy.DisableFileSyncNGSC -eq 1) {
    Write-Host "  [OK] Reinstall prevention policy set (DisableFileSyncNGSC = 1)" -ForegroundColor Green
} else {
    Write-Host "  [!!] Reinstall prevention policy NOT set" -ForegroundColor Yellow
}

Write-Host ""
