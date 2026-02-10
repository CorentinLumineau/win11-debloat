#Requires -RunAsAdministrator
# Remediation script - applies all debloat settings + date format fix
$ErrorActionPreference = 'SilentlyContinue'

function Set-Reg {
    param([string]$Path, [string]$Name, $Value, [string]$Type = "DWord")
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
}

Write-Host "`n=== SAFETY ===" -ForegroundColor Cyan
Enable-ComputerRestore -Drive "C:\"
Checkpoint-Computer -Description "Pre-Debloat Fix" -RestorePointType MODIFY_SETTINGS -ErrorAction SilentlyContinue
Write-Host "  Restore point created" -ForegroundColor Green

$backupDir = Join-Path $PSScriptRoot "registry-backup"
if (-not (Test-Path $backupDir)) { New-Item -Path $backupDir -ItemType Directory -Force | Out-Null }
$ts = Get-Date -Format "yyyyMMdd-HHmmss"
reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows" "$backupDir\HKLM_Policies_$ts.reg" /y 2>$null
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion" "$backupDir\HKLM_CurrentVersion_$ts.reg" /y 2>$null
reg export "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion" "$backupDir\HKCU_CurrentVersion_$ts.reg" /y 2>$null
reg export "HKLM\SYSTEM\CurrentControlSet\Services" "$backupDir\HKLM_Services_$ts.reg" /y 2>$null
Write-Host "  Registry backed up" -ForegroundColor Green

# === TELEMETRY ===
Write-Host "`n=== TELEMETRY ===" -ForegroundColor Cyan

Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry" 0
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "MaxTelemetryAllowed" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" "DisabledByGroupPolicy" 1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableActivityFeed" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "PublishUserActivities" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "UploadUserActivities" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" "NumberOfSIUFInPeriod" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" "PeriodInNanoSeconds" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DoNotShowFeedbackNotifications" 1
Set-Reg "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableTailoredExperiencesWithDiagnosticData" 1
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" "TailoredExperiencesWithDiagnosticDataEnabled" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitInkCollection" 1
Set-Reg "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitTextCollection" 1
Set-Reg "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" "HarvestContacts" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" "AcceptedPrivacyPolicy" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Start_TrackProgs" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" "DisableLocation" 1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" "DisableWindowsLocationProvider" 1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" "DisableLocationScripting" 1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" "CEIPEnable" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" "CEIPEnable" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" "AITEnable" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" "DisableInventory" 1
Write-Host "  Registry keys set" -ForegroundColor Green

# Telemetry services
foreach ($sn in @('DiagTrack','dmwappushservice','diagnosticshub.standardcollector.service')) {
    Stop-Service -Name $sn -Force -ErrorAction SilentlyContinue
    Set-Service -Name $sn -StartupType Disabled -ErrorAction SilentlyContinue
}
Write-Host "  Telemetry services disabled" -ForegroundColor Green

# Telemetry scheduled tasks
$tasks = @(
    'Microsoft Compatibility Appraiser',
    'ProgramDataUpdater'
)
foreach ($t in $tasks) {
    Disable-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue | Out-Null
}
foreach ($tp in @('\Microsoft\Windows\Customer Experience Improvement Program\','\Microsoft\Windows\Feedback\Siuf\')) {
    Get-ScheduledTask -TaskPath $tp -ErrorAction SilentlyContinue | Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null
}
Write-Host "  Telemetry tasks disabled" -ForegroundColor Green

# === BLOATWARE ===
Write-Host "`n=== BLOATWARE ===" -ForegroundColor Cyan

$removeApps = @(
    "Microsoft.3DBuilder","Microsoft.Microsoft3DViewer","Microsoft.Print3D",
    "Microsoft.BingWeather","Microsoft.BingNews","Microsoft.BingFinance","Microsoft.BingSports",
    "Microsoft.GetHelp","Microsoft.Getstarted","Microsoft.Messaging",
    "Microsoft.MicrosoftOfficeHub","Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.MixedReality.Portal","Microsoft.OneConnect","Microsoft.People",
    "Microsoft.SkypeApp","Microsoft.Todos","Microsoft.WindowsAlarms",
    "Microsoft.WindowsFeedbackHub","Microsoft.WindowsMaps","Microsoft.WindowsSoundRecorder",
    "Microsoft.YourPhone","Microsoft.ZuneMusic","Microsoft.ZuneVideo",
    "Microsoft.PowerAutomateDesktop","Microsoft.Clipchamp","MicrosoftTeams",
    "Microsoft.OutlookForWindows","Microsoft.549981C3F5F10",
    "Microsoft.WindowsCommunicationsApps","Microsoft.MicrosoftStickyNotes",
    "Microsoft.Copilot","Microsoft.Windows.Ai.Copilot.Provider","Microsoft.OneDrive"
)
$wildcards = @("*CandyCrush*","*EclipseManager*","*ActiproSoftware*","*Duolingo*","*SpotifyAB*","*Disney*","*Facebook*","*Twitter*","*TikTok*","*Amazon*","*Netflix*","*BubbleWitch*")

foreach ($app in $removeApps) {
    Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -like "*$app*" } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null
}
foreach ($w in $wildcards) {
    Get-AppxPackage -AllUsers | Where-Object { $_.Name -like $w } | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -like $w } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null
}
# OneDrive (Win32 app)
Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
$od = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
if (-not (Test-Path $od)) { $od = "$env:SystemRoot\System32\OneDriveSetup.exe" }
if (Test-Path $od) { Start-Process $od "/uninstall" -Wait -ErrorAction SilentlyContinue }
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1
Write-Host "  Bloatware removed (including OneDrive)" -ForegroundColor Green

# === SEARCH / CORTANA ===
Write-Host "`n=== SEARCH / CORTANA ===" -ForegroundColor Cyan

Stop-Service -Name "WSearch" -Force -ErrorAction SilentlyContinue
Set-Service -Name "WSearch" -StartupType Disabled -ErrorAction SilentlyContinue
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortanaAboveLock" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "BingSearchEnabled" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "CortanaConsent" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "DisableWebSearch" 1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "ConnectedSearchUseWeb" 0
Set-Reg "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "DisableSearchBoxSuggestions" 1
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "SearchboxTaskbarMode" 0
Write-Host "  Search and Cortana disabled" -ForegroundColor Green

# === SMARTSCREEN ===
Write-Host "`n=== SMARTSCREEN ===" -ForegroundColor Cyan

Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" "SmartScreenEnabled" "Off" "String"
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableSmartScreen" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "ShellSmartScreenLevel" "Warn" "String"
Set-Reg "HKCU:\SOFTWARE\Microsoft\Edge\SmartScreenEnabled" "(Default)" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Edge" "SmartScreenEnabled" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" "EnableWebContentEvaluation" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" "PreventOverride" 0
Write-Host "  SmartScreen disabled (Defender untouched)" -ForegroundColor Green

# === VISUAL EFFECTS ===
Write-Host "`n=== VISUAL EFFECTS ===" -ForegroundColor Cyan

Set-Reg "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" "VisualFXSetting" 3
$mask = [byte[]](0x90, 0x12, 0x01, 0x80, 0x10, 0x00, 0x00, 0x00)
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Value $mask -Type Binary -Force
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\DWM" "EnableAeroPeek" 1
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" "EnableTransparency" 1
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "FontSmoothing" -Value "2" -Force
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "FontSmoothingType" -Value 2 -Force
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ListviewSmoothScrolling" 1
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value "1" -Force
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Value "1" -Force
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "TaskbarAnimations" 0
Write-Host "  Visual effects set (Balanced)" -ForegroundColor Green

# === BACKGROUND SERVICES ===
Write-Host "`n=== BACKGROUND SERVICES ===" -ForegroundColor Cyan

Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" "GlobalUserDisabled" 1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsRunInBackground" 2

foreach ($sn in @('SysMain','RemoteRegistry','TermService','SessionEnv','UmRdpService','Fax','MapsBroker','lfsvc','RetailDemo','wisvc','WerSvc')) {
    Stop-Service -Name $sn -Force -ErrorAction SilentlyContinue
    Set-Service -Name $sn -StartupType Disabled -ErrorAction SilentlyContinue
}
Write-Host "  Services disabled" -ForegroundColor Green

# === TASKBAR / SHELL ===
Write-Host "`n=== TASKBAR / SHELL ===" -ForegroundColor Cyan

$cdm = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
$adv = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"

foreach ($key in @(
    "SubscribedContent-310093Enabled","SubscribedContent-314563Enabled",
    "SubscribedContent-338387Enabled","SubscribedContent-338388Enabled",
    "SubscribedContent-338389Enabled","SubscribedContent-338393Enabled",
    "SubscribedContent-353694Enabled","SubscribedContent-353696Enabled",
    "SubscribedContent-353698Enabled"
)) {
    Set-Reg $cdm $key 0
}
Set-Reg $cdm "SilentInstalledAppsEnabled" 0
Set-Reg $cdm "SystemPaneSuggestionsEnabled" 0
Set-Reg $cdm "SoftLandingEnabled" 0
Set-Reg $cdm "RotatingLockScreenEnabled" 0
Set-Reg $cdm "RotatingLockScreenOverlayEnabled" 0

Set-Reg $adv "TaskbarDa" 0
Set-Reg $adv "TaskbarMn" 0
Set-Reg $adv "ShowCopilotButton" 0
Set-Reg "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" "TurnOffWindowsCopilot" 1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" "TurnOffWindowsCopilot" 1
Set-Reg $adv "ShowTaskViewButton" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" "AllowNewsAndInterests" 0

# Classic right-click context menu
$clsid = "HKCU:\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
if (-not (Test-Path $clsid)) { New-Item -Path $clsid -Force | Out-Null }
Set-ItemProperty -Path $clsid -Name "(Default)" -Value "" -Force

Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableCloudOptimizedContent" 1
Write-Host "  Taskbar and shell cleaned" -ForegroundColor Green

# === NETWORK ===
Write-Host "`n=== NETWORK ===" -ForegroundColor Cyan

$tcpParams = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
Set-Reg $tcpParams "TcpAckFrequency" 1
Set-Reg $tcpParams "TCPNoDelay" 1
Set-Reg $tcpParams "TcpTimedWaitDelay" 30

# Apply to all interfaces
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" -ErrorAction SilentlyContinue | ForEach-Object {
    Set-Reg $_.PSPath "TcpAckFrequency" 1
    Set-Reg $_.PSPath "TCPNoDelay" 1
}

Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "NetworkThrottlingIndex" 0xffffffff
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "SystemResponsiveness" 0
Set-Reg "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" "AutoConnectAllowedOEM" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" "NonBestEffortLimit" 0

# Gaming MMCSS
$mmcss = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"
Set-Reg $mmcss "GPU Priority" 8
Set-Reg $mmcss "Priority" 6
Set-Reg $mmcss "Scheduling Category" "High" "String"
Set-Reg $mmcss "SFIO Priority" "High" "String"

# Disable LSO
Get-NetAdapterAdvancedProperty -DisplayName "Large Send Offload*" -ErrorAction SilentlyContinue | ForEach-Object {
    Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName $_.DisplayName -DisplayValue "Disabled" -ErrorAction SilentlyContinue
}
Write-Host "  Network optimized" -ForegroundColor Green

# === POWER PLAN ===
Write-Host "`n=== POWER PLAN ===" -ForegroundColor Cyan

powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2>$null
$plan = powercfg /getactivescheme 2>&1
if ($plan -notmatch "High performance") {
    # Try Ultimate Performance
    powercfg /setactive e9a42b02-d5df-448d-aa00-03f14749eb61 2>$null
}
# USB selective suspend off
powercfg /setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
powercfg /setdcvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
powercfg /change disk-timeout-ac 0
powercfg /change disk-timeout-dc 0
powercfg /change monitor-timeout-ac 0
powercfg /change monitor-timeout-dc 0
powercfg /change standby-timeout-ac 0
powercfg /change standby-timeout-dc 0
powercfg /change hibernate-timeout-ac 0
powercfg /change hibernate-timeout-dc 0
powercfg /hibernate off
powercfg /setactive scheme_current 2>$null
Write-Host "  Power plan set (no sleep, no screen off)" -ForegroundColor Green

# === DATE FORMAT ===
Write-Host "`n=== DATE FORMAT ===" -ForegroundColor Cyan

Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name "sShortDate" -Value "dd/MM/yyyy" -Force
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name "sLongDate" -Value "dddd d MMMM yyyy" -Force
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name "iDate" -Value "1" -Force
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name "sDate" -Value "/" -Force
Write-Host "  Date format set to dd/MM/yyyy" -ForegroundColor Green

# === RESTART EXPLORER ===
Write-Host "`n=== FINALIZING ===" -ForegroundColor Cyan
Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Start-Process explorer
Write-Host "  Explorer restarted" -ForegroundColor Green

Write-Host "`n=== ALL DONE ===" -ForegroundColor Green
Write-Host "  Reboot recommended to apply all changes.`n" -ForegroundColor Yellow
