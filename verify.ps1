$ErrorActionPreference = 'SilentlyContinue'

function Check($label, $actual, $expected) {
    if ($actual -eq $expected) {
        Write-Host "  [OK] $label = $actual" -ForegroundColor Green
    } else {
        Write-Host "  [!!] $label = $actual (expected $expected)" -ForegroundColor Red
    }
}

function CheckNot($label, $actual, $bad) {
    if ($actual -ne $bad) {
        Write-Host "  [OK] $label = $actual" -ForegroundColor Green
    } else {
        Write-Host "  [!!] $label = $actual (should not be $bad)" -ForegroundColor Red
    }
}

# ============================================
Write-Host "`n=== SECTION 0: SAFETY ===" -ForegroundColor Cyan
$backups = Get-ChildItem "$PSScriptRoot\registry-backup\*.reg" -EA SilentlyContinue
if ($backups.Count -ge 1) {
    Write-Host "  [OK] Registry backups found: $($backups.Count) files" -ForegroundColor Green
    $backups | ForEach-Object { Write-Host "       $($_.Name)" -ForegroundColor DarkGray }
} else {
    Write-Host "  [!!] No registry backups found" -ForegroundColor Red
}

# ============================================
Write-Host "`n=== SECTION 1: TELEMETRY ===" -ForegroundColor Cyan

# Services
foreach ($sn in @('DiagTrack','dmwappushservice')) {
    $svc = Get-Service $sn -EA SilentlyContinue
    if ($svc) {
        Check "$sn Status" $svc.Status "Stopped"
        Check "$sn StartType" $svc.StartupType "Disabled"
    } else {
        Write-Host "  [OK] $sn not found (already removed)" -ForegroundColor Green
    }
}

# Registry
$r = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -EA SilentlyContinue
Check "AllowTelemetry" $r.AllowTelemetry 0

$r = Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -EA SilentlyContinue
Check "AdvertisingID Enabled" $r.Enabled 0

$r = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -EA SilentlyContinue
Check "PublishUserActivities" $r.PublishUserActivities 0
Check "EnableActivityFeed" $r.EnableActivityFeed 0

$r = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -EA SilentlyContinue
Check "DisableLocation" $r.DisableLocation 1

$r = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' -EA SilentlyContinue
Check "AITEnable (Appraiser)" $r.AITEnable 0

$r = Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -EA SilentlyContinue
Check "Start_TrackProgs" $r.Start_TrackProgs 0

# ============================================
Write-Host "`n=== SECTION 2: BLOATWARE ===" -ForegroundColor Cyan

Write-Host "  Should be REMOVED:" -ForegroundColor White
$removed = @(
    'Microsoft.BingWeather','Microsoft.GetHelp','Microsoft.People',
    'Microsoft.WindowsFeedbackHub','Microsoft.ZuneMusic','Microsoft.ZuneVideo',
    'Microsoft.YourPhone','Microsoft.549981C3F5F10','Microsoft.Clipchamp',
    'Microsoft.OutlookForWindows','Microsoft.WindowsCommunicationsApps',
    'Microsoft.MicrosoftSolitaireCollection','Microsoft.Copilot',
    'Microsoft.MicrosoftOfficeHub','Microsoft.Todos','Microsoft.SkypeApp',
    'Microsoft.MixedReality.Portal','Microsoft.WindowsMaps',
    'Microsoft.PowerAutomateDesktop','Microsoft.MicrosoftStickyNotes'
)
foreach ($app in $removed) {
    $p = Get-AppxPackage -Name $app -EA SilentlyContinue
    if ($p) {
        Write-Host "  [!!] STILL PRESENT: $app" -ForegroundColor Red
    } else {
        Write-Host "  [OK] Removed: $app" -ForegroundColor Green
    }
}

Write-Host "`n  Should be KEPT:" -ForegroundColor White
$kept = @(
    'Microsoft.WindowsStore','Microsoft.WindowsCalculator',
    'Microsoft.Windows.Photos','Microsoft.WindowsTerminal',
    'Microsoft.XboxGamingOverlay'
)
foreach ($app in $kept) {
    $p = Get-AppxPackage -Name $app -EA SilentlyContinue
    if ($p) {
        Write-Host "  [OK] Present: $app" -ForegroundColor Green
    } else {
        Write-Host "  [!!] MISSING: $app" -ForegroundColor Red
    }
}

# ============================================
Write-Host "`n=== SECTION 3: SEARCH / CORTANA ===" -ForegroundColor Cyan

$svc = Get-Service WSearch -EA SilentlyContinue
if ($svc) {
    Check "WSearch StartType" $svc.StartupType "Disabled"
}

$r = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -EA SilentlyContinue
Check "AllowCortana" $r.AllowCortana 0

$r = Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' -EA SilentlyContinue
Check "BingSearchEnabled" $r.BingSearchEnabled 0
Check "SearchboxTaskbarMode" $r.SearchboxTaskbarMode 0

# ============================================
Write-Host "`n=== SECTION 4: SMARTSCREEN / DEFENDER ===" -ForegroundColor Cyan

$r = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -EA SilentlyContinue
Check "SmartScreenEnabled" $r.SmartScreenEnabled "Off"

$r = Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost' -EA SilentlyContinue
Check "Store SmartScreen" $r.EnableWebContentEvaluation 0

Write-Host "`n  Defender (should be ON):" -ForegroundColor White
$def = Get-MpComputerStatus -EA SilentlyContinue
if ($def) {
    Check "AntivirusEnabled" $def.AntivirusEnabled $true
    Check "RealTimeProtection" $def.RealTimeProtectionEnabled $true
    Check "AntispywareEnabled" $def.AntispywareEnabled $true
} else {
    Write-Host "  [??] Could not query Defender status" -ForegroundColor Yellow
}

# ============================================
Write-Host "`n=== SECTION 5: VISUAL EFFECTS ===" -ForegroundColor Cyan

$r = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -EA SilentlyContinue
Check "VisualFXSetting (3=Custom)" $r.VisualFXSetting 3

$r = Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' -EA SilentlyContinue
Check "Transparency" $r.EnableTransparency 1

$r = Get-ItemProperty 'HKCU:\Control Panel\Desktop' -EA SilentlyContinue
Check "FontSmoothing (ClearType)" $r.FontSmoothing "2"

# ============================================
Write-Host "`n=== SECTION 6: BACKGROUND SERVICES ===" -ForegroundColor Cyan

$r = Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications' -EA SilentlyContinue
Check "GlobalUserDisabled (bg apps)" $r.GlobalUserDisabled 1

Write-Host "`n  Should be DISABLED:" -ForegroundColor White
foreach ($sn in @('RemoteRegistry','TermService','Fax','MapsBroker','lfsvc','WerSvc','SysMain','wisvc')) {
    $svc = Get-Service $sn -EA SilentlyContinue
    if ($svc) {
        if ($svc.StartupType -eq 'Disabled') {
            Write-Host "  [OK] $sn = Disabled" -ForegroundColor Green
        } else {
            Write-Host "  [!!] $sn = $($svc.StartupType) (expected Disabled)" -ForegroundColor Red
        }
    } else {
        Write-Host "  [OK] $sn not found" -ForegroundColor Green
    }
}

Write-Host "`n  Should be KEPT:" -ForegroundColor White
foreach ($sn in @('bthserv','Spooler','LxssManager','HvHost')) {
    $svc = Get-Service $sn -EA SilentlyContinue
    if ($svc) {
        if ($svc.StartupType -ne 'Disabled') {
            Write-Host "  [OK] $sn = $($svc.Status) / $($svc.StartupType)" -ForegroundColor Green
        } else {
            Write-Host "  [!!] $sn is Disabled (should be kept)" -ForegroundColor Red
        }
    } else {
        Write-Host "  [--] $sn not installed" -ForegroundColor DarkGray
    }
}

# ============================================
Write-Host "`n=== SECTION 7: TASKBAR / SHELL ===" -ForegroundColor Cyan

$adv = Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -EA SilentlyContinue
Check "Widgets (TaskbarDa)" $adv.TaskbarDa 0
Check "Chat (TaskbarMn)" $adv.TaskbarMn 0
Check "Copilot button" $adv.ShowCopilotButton 0
Check "Task View button" $adv.ShowTaskViewButton 0

$ctx = Test-Path 'HKCU:\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32'
Check "Classic context menu key" $ctx $true

$r = Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -EA SilentlyContinue
Check "SilentInstalledApps" $r.SilentInstalledAppsEnabled 0

# ============================================
Write-Host "`n=== SECTION 8: NETWORK ===" -ForegroundColor Cyan

$tcp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -EA SilentlyContinue
Check "TcpAckFrequency" $tcp.TcpAckFrequency 1
Check "TCPNoDelay" $tcp.TCPNoDelay 1
Check "TcpTimedWaitDelay" $tcp.TcpTimedWaitDelay 30

$mm = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' -EA SilentlyContinue
Check "NetworkThrottlingIndex" $mm.NetworkThrottlingIndex 4294967295
Check "SystemResponsiveness" $mm.SystemResponsiveness 0

$qos = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched' -EA SilentlyContinue
Check "QoS NonBestEffortLimit" $qos.NonBestEffortLimit 0

# ============================================
Write-Host "`n=== SECTION 9: POWER PLAN ===" -ForegroundColor Cyan

$plan = powercfg /getactivescheme 2>&1
Write-Host "  Active: $plan" -ForegroundColor White

# Monitor timeout
$mon = powercfg /query scheme_current 7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e 2>&1
$acMon = ($mon | Select-String 'Current AC Power Setting Index:') -replace '.*:\s*', ''
Check "Monitor timeout AC" $acMon "0x00000000"

# Standby timeout
$sb = powercfg /query scheme_current 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 2>&1
$acSb = ($sb | Select-String 'Current AC Power Setting Index:') -replace '.*:\s*', ''
Check "Standby timeout AC" $acSb "0x00000000"

# Hibernate
$hib = powercfg /query scheme_current 238c9fa8-0aad-41ed-83f4-97be242c8f20 9d7815a6-7ee4-497e-8888-515a05f02364 2>&1
$acHib = ($hib | Select-String 'Current AC Power Setting Index:') -replace '.*:\s*', ''
Check "Hibernate timeout AC" $acHib "0x00000000"

# ============================================
Write-Host "`n=== DATE FORMAT ===" -ForegroundColor Cyan
$df = Get-ItemProperty 'HKCU:\Control Panel\International' -EA SilentlyContinue
Write-Host "  Short date: $($df.sShortDate)" -ForegroundColor White
Write-Host "  Long date:  $($df.sLongDate)" -ForegroundColor White

# ============================================
Write-Host "`n=== SUMMARY ===" -ForegroundColor Magenta
Write-Host "  Review items marked [!!] above for anything that needs attention." -ForegroundColor Yellow
Write-Host ""
