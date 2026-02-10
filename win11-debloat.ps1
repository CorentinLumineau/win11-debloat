#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows 11 Custom Debloat andOptimization Script
.DESCRIPTION
    Removes bloatware, kills telemetry, optimizes performance, and cleans up the UI.
    Tailored for Gaming + Dev + Browsing workloads.
.NOTES
    Run as Administrator:
    powershell -ExecutionPolicy Bypass -File .\win11-debloat.ps1
#>

$ErrorActionPreference = 'SilentlyContinue'

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Banner {
    param([string]$Title)
    $line = "=" * 70
    Write-Host "`n$line" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor White
    Write-Host "$line`n" -ForegroundColor Cyan
}

function Write-Step {
    param([string]$Message)
    Write-Host "  [*] $Message" -ForegroundColor Yellow
}

function Write-Done {
    param([string]$Message)
    Write-Host "  [+] $Message" -ForegroundColor Green
}

function Write-Skip {
    param([string]$Message)
    Write-Host "  [-] $Message" -ForegroundColor DarkGray
}

function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWord"
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
}

function Disable-ScheduledTaskSafe {
    param([string]$TaskName)
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task -and $task.State -ne 'Disabled') {
        Disable-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Out-Null
        Write-Done "Disabled task: $TaskName"
    }
    elseif ($task) {
        Write-Skip "Already disabled: $TaskName"
    }
    else {
        Write-Skip "Task not found: $TaskName"
    }
}

function Disable-ServiceSafe {
    param([string]$ServiceName)
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Done "Disabled service: $ServiceName ($($svc.DisplayName))"
    }
    else {
        Write-Skip "Service not found: $ServiceName"
    }
}

# ============================================================================
# SECTION 0: Safety - Restore Point andRegistry Backup
# ============================================================================

function Invoke-SafetyBackup {
    Write-Banner "SECTION 0: Safety - Restore Point andRegistry Backup"

    # Verify admin privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
    if (-not $isAdmin) {
        Write-Host "  [!] ERROR: This script must be run as Administrator." -ForegroundColor Red
        Write-Host "  [!] Right-click PowerShell > Run as Administrator, then re-run." -ForegroundColor Red
        exit 1
    }
    Write-Done "Running with Administrator privileges"

    # Create restore point
    Write-Step "Creating System Restore point..."
    Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue
    Checkpoint-Computer -Description "Pre-Debloat Restore Point" -RestorePointType MODIFY_SETTINGS -ErrorAction SilentlyContinue
    Write-Done "System Restore point created"

    # Registry backup
    $backupDir = Join-Path $PSScriptRoot "registry-backup"
    if (-not (Test-Path $backupDir)) {
        New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
    }
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

    Write-Step "Exporting registry backups to .\registry-backup\ ..."

    $exports = @{
        "HKLM_Policies"       = "HKLM\SOFTWARE\Policies\Microsoft\Windows"
        "HKLM_CurrentVersion" = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion"
        "HKCU_CurrentVersion" = "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion"
        "HKLM_Services"       = "HKLM\SYSTEM\CurrentControlSet\Services"
    }

    foreach ($name in $exports.Keys) {
        $file = Join-Path $backupDir "${name}_${timestamp}.reg"
        $key = $exports[$name]
        reg export $key $file /y 2>$null | Out-Null
        if (Test-Path $file) {
            Write-Done "Exported $name"
        }
        else {
            Write-Skip "Could not export $name (key may not exist)"
        }
    }
}

# ============================================================================
# SECTION 1: Telemetry - Kill Everything
# ============================================================================

function Invoke-TelemetryKill {
    Write-Banner "SECTION 1: Telemetry - Kill Everything"

    # --- Registry keys ---
    Write-Step "Setting telemetry registry keys..."

    # AllowTelemetry = 0 (Security level / off)
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry" 0
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "MaxTelemetryAllowed" 0
    Write-Done "Telemetry level set to 0 (Security)"

    # Disable Advertising ID
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" "DisabledByGroupPolicy" 1
    Write-Done "Advertising ID disabled"

    # Disable Activity History
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableActivityFeed" 0
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "PublishUserActivities" 0
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "UploadUserActivities" 0
    Write-Done "Activity History disabled"

    # Disable Feedback Notifications
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" "NumberOfSIUFInPeriod" 0
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" "PeriodInNanoSeconds" 0
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DoNotShowFeedbackNotifications" 1
    Write-Done "Feedback notifications disabled"

    # Disable Tailored Experiences
    Set-RegistryValue "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableTailoredExperiencesWithDiagnosticData" 1
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" "TailoredExperiencesWithDiagnosticDataEnabled" 0
    Write-Done "Tailored Experiences disabled"

    # Disable Input Personalization / Inking andTyping
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitInkCollection" 1
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitTextCollection" 1
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" "HarvestContacts" 0
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" "AcceptedPrivacyPolicy" 0
    Write-Done "Input Personalization / Inking andTyping disabled"

    # Disable App Launch Tracking
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Start_TrackProgs" 0
    Write-Done "App Launch Tracking disabled"

    # Disable Location tracking
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" "DisableLocation" 1
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" "DisableWindowsLocationProvider" 1
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" "DisableLocationScripting" 1
    Write-Done "Location tracking disabled"

    # Disable CEIP
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" "CEIPEnable" 0
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" "CEIPEnable" 0
    Write-Done "Customer Experience Improvement Program (CEIP) disabled"

    # Disable Application Compatibility telemetry (Appraiser)
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" "AITEnable" 0
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" "DisableInventory" 1
    Write-Done "Application Compatibility telemetry disabled"

    # --- Services ---
    Write-Step "Disabling telemetry services..."
    Disable-ServiceSafe "DiagTrack"
    Disable-ServiceSafe "dmwappushservice"
    Disable-ServiceSafe "diagnosticshub.standardcollector.service"

    # --- Scheduled Tasks ---
    Write-Step "Disabling telemetry scheduled tasks..."

    $telemetryTasks = @(
        "Microsoft Compatibility Appraiser"
        "ProgramDataUpdater"
    )
    foreach ($task in $telemetryTasks) {
        Disable-ScheduledTaskSafe $task
    }

    # Tasks in specific paths (use full task path)
    $taskPaths = @(
        "\Microsoft\Windows\Autochk\ProactiveScan"
        "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
        "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
    )
    foreach ($tp in $taskPaths) {
        $t = Get-ScheduledTask -TaskPath ($tp -replace '[^\\]*$','') -TaskName ($tp -split '\\')[-1] -ErrorAction SilentlyContinue
        if ($t -and $t.State -ne 'Disabled') {
            $t | Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null
            Write-Done "Disabled task: $tp"
        }
        elseif ($t) { Write-Skip "Already disabled: $tp" }
        else { Write-Skip "Task not found: $tp" }
    }

    # Wildcard task folders
    $wildcardPaths = @(
        "\Microsoft\Windows\Customer Experience Improvement Program\"
        "\Microsoft\Windows\Feedback\Siuf\"
    )
    foreach ($wp in $wildcardPaths) {
        $tasks = Get-ScheduledTask -TaskPath $wp -ErrorAction SilentlyContinue
        foreach ($t in $tasks) {
            if ($t.State -ne 'Disabled') {
                $t | Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null
                Write-Done "Disabled task: $wp$($t.TaskName)"
            }
            else { Write-Skip "Already disabled: $wp$($t.TaskName)" }
        }
    }
}

# ============================================================================
# SECTION 2: Bloatware Removal
# ============================================================================

function Invoke-BloatwareRemoval {
    Write-Banner "SECTION 2: Bloatware Removal"

    # Apps to keep (exact package name fragments)
    $keepApps = @(
        "Microsoft.WindowsStore"
        "Microsoft.XboxApp"
        "Microsoft.Xbox.TCUI"
        "Microsoft.XboxGameOverlay"
        "Microsoft.XboxGamingOverlay"
        "Microsoft.XboxIdentityProvider"
        "Microsoft.XboxSpeechToTextOverlay"
        "Microsoft.WindowsCalculator"
        "Microsoft.Windows.Photos"
        "Microsoft.WindowsTerminal"
        "Microsoft.DesktopAppInstaller"  # Needed for winget
    )

    # Exact apps to remove
    $removeApps = @(
        "Microsoft.3DBuilder"
        "Microsoft.Microsoft3DViewer"
        "Microsoft.Print3D"
        "Microsoft.BingWeather"
        "Microsoft.BingNews"
        "Microsoft.BingFinance"
        "Microsoft.BingSports"
        "Microsoft.GetHelp"
        "Microsoft.Getstarted"
        "Microsoft.Messaging"
        "Microsoft.MicrosoftOfficeHub"
        "Microsoft.MicrosoftSolitaireCollection"
        "Microsoft.MixedReality.Portal"
        "Microsoft.OneConnect"
        "Microsoft.People"
        "Microsoft.SkypeApp"
        "Microsoft.Todos"
        "Microsoft.WindowsAlarms"
        "Microsoft.WindowsFeedbackHub"
        "Microsoft.WindowsMaps"
        "Microsoft.WindowsSoundRecorder"
        "Microsoft.YourPhone"
        "Microsoft.ZuneMusic"
        "Microsoft.ZuneVideo"
        "Microsoft.PowerAutomateDesktop"
        "Microsoft.Clipchamp"
        "MicrosoftTeams"
        "Microsoft.OutlookForWindows"
        "Microsoft.549981C3F5F10"
        "Microsoft.WindowsCommunicationsApps"
        "Microsoft.MicrosoftStickyNotes"
        "Microsoft.Copilot"
        "Microsoft.Windows.Ai.Copilot.Provider"
        "Microsoft.OneDrive"
    )

    # Wildcard patterns for third-party bloat
    $wildcardPatterns = @(
        "*CandyCrush*"
        "*EclipseManager*"
        "*ActiproSoftware*"
        "*Duolingo*"
        "*SpotifyAB*"
        "*Disney*"
        "*Facebook*"
        "*Twitter*"
        "*TikTok*"
        "*Amazon*"
        "*Netflix*"
        "*BubbleWitch*"
        "*Wunderlist*"
        "*Flipboard*"
        "*Royal Revolt*"
        "*Sway*"
        "*Dolby*"
    )

    # Remove exact-match apps
    Write-Step "Removing Microsoft bloatware..."
    foreach ($app in $removeApps) {
        $pkg = Get-AppxPackage -Name $app -AllUsers -ErrorAction SilentlyContinue
        if ($pkg) {
            $pkg | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
            Write-Done "Removed: $app"
        }
        else {
            Write-Skip "Not installed: $app"
        }

        # Also remove provisioned package to prevent reinstall
        $prov = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
            Where-Object { $_.PackageName -like "*$app*" }
        if ($prov) {
            $prov | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null
        }
    }

    # Remove wildcard-match apps
    Write-Step "Removing third-party bloatware..."
    foreach ($pattern in $wildcardPatterns) {
        $pkgs = Get-AppxPackage -AllUsers | Where-Object { $_.Name -like $pattern }
        foreach ($pkg in $pkgs) {
            # Safety check: don't remove kept apps
            $isKept = $false
            foreach ($keep in $keepApps) {
                if ($pkg.Name -like "*$keep*") { $isKept = $true; break }
            }
            if (-not $isKept) {
                $pkg | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
                Write-Done "Removed: $($pkg.Name)"
            }
        }

        # Provisioned packages
        $provs = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
            Where-Object { $_.PackageName -like $pattern }
        foreach ($prov in $provs) {
            $prov | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null
        }
    }

    # OneDrive (Win32 app, not always caught by AppxPackage)
    Write-Step "Removing OneDrive..."
    Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
    $onedrive64 = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
    $onedrive32 = "$env:SystemRoot\System32\OneDriveSetup.exe"
    if (Test-Path $onedrive64) {
        Start-Process $onedrive64 "/uninstall" -Wait -ErrorAction SilentlyContinue
        Write-Done "OneDrive uninstalled (64-bit)"
    } elseif (Test-Path $onedrive32) {
        Start-Process $onedrive32 "/uninstall" -Wait -ErrorAction SilentlyContinue
        Write-Done "OneDrive uninstalled (32-bit)"
    } else {
        Write-Skip "OneDrive setup not found (already removed)"
    }
    # Prevent OneDrive from reinstalling
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1

    Write-Done "Bloatware removal complete"
}

# ============================================================================
# SECTION 3: Disable Windows Search andCortana
# ============================================================================

function Invoke-SearchCortanaDisable {
    Write-Banner "SECTION 3: Disable Windows Search andCortana"

    # Disable Windows Search service
    Write-Step "Disabling Windows Search service..."
    Disable-ServiceSafe "WSearch"

    # Disable Cortana
    Write-Step "Disabling Cortana..."
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana" 0
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortanaAboveLock" 0
    Write-Done "Cortana disabled"

    # Disable Bing/web search in Start menu
    Write-Step "Disabling Bing search in Start menu..."
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "BingSearchEnabled" 0
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "CortanaConsent" 0
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "DisableWebSearch" 1
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "ConnectedSearchUseWeb" 0
    Set-RegistryValue "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "DisableSearchBoxSuggestions" 1
    Write-Done "Bing search in Start menu disabled"

    # Hide Search icon from taskbar
    Write-Step "Hiding Search from taskbar..."
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "SearchboxTaskbarMode" 0
    Write-Done "Search icon hidden from taskbar"
}

# ============================================================================
# SECTION 4: Windows Defender - SmartScreen Only
# ============================================================================

function Invoke-SmartScreenDisable {
    Write-Banner "SECTION 4: Windows Defender - Disable SmartScreen Only"

    Write-Step "Disabling SmartScreen for Windows Explorer..."
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" "SmartScreenEnabled" "Off" "String"
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableSmartScreen" 0
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "ShellSmartScreenLevel" "Warn" "String"
    Write-Done "SmartScreen for Windows disabled"

    Write-Step "Disabling SmartScreen for Edge..."
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Edge\SmartScreenEnabled" "(Default)" 0
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Edge" "SmartScreenEnabled" 0
    Write-Done "SmartScreen for Edge disabled"

    Write-Step "Disabling SmartScreen for Store apps..."
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" "EnableWebContentEvaluation" 0
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" "PreventOverride" 0
    Write-Done "SmartScreen for Store apps disabled"

    Write-Host "`n  [i] Defender real-time protection and cloud delivery are UNTOUCHED." -ForegroundColor Cyan
}

# ============================================================================
# SECTION 5: Visual Effects - Balanced
# ============================================================================

function Invoke-VisualEffectsOptimize {
    Write-Banner "SECTION 5: Visual Effects - Balanced"

    Write-Step "Configuring visual effects (Custom mode)..."

    $vfxPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
    $advPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    $dwmPath = "HKCU:\SOFTWARE\Microsoft\Windows\DWM"

    # Set to Custom visual effects
    Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" "VisualFXSetting" 3

    # UserPreferencesMask - this binary blob controls individual effects.
    # We set a balanced profile: keep animations + transparency, disable heavy effects.
    # Bits: smooth-scroll=ON, animate-windows=ON, fade-menus=OFF, slide-menus=OFF, etc.
    # Balanced preset value (keep transparency, font smoothing, window animations):
    $mask = [byte[]](0x90, 0x12, 0x01, 0x80, 0x10, 0x00, 0x00, 0x00)
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Value $mask -Type Binary -Force

    # Keep transparency
    Set-RegistryValue $dwmPath "EnableAeroPeek" 1
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" "EnableTransparency" 1
    Write-Done "Transparency enabled"

    # Keep font smoothing (ClearType)
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "FontSmoothing" -Value "2" -Force
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "FontSmoothingType" -Value 2 -Force
    Write-Done "ClearType font smoothing enabled"

    # Keep smooth scrolling (handled by apps, but ensure ListviewSmoothScrolling is on)
    Set-RegistryValue $advPath "ListviewSmoothScrolling" 1
    Write-Done "Smooth scrolling enabled"

    # Keep window minimize/maximize animations
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value "1" -Force
    Write-Done "Window animations enabled"

    # Disable tooltip fade/animations
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Value $mask -Type Binary -Force

    # Disable showing window contents while dragging (saves GPU during drag)
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Value "1" -Force

    # Disable taskbar animations
    Set-RegistryValue $advPath "TaskbarAnimations" 0
    Write-Done "Taskbar animations disabled"

    Write-Done "Visual effects configured (Balanced)"
}

# ============================================================================
# SECTION 6: Background Apps andServices - Moderate Cleanup
# ============================================================================

function Invoke-BackgroundCleanup {
    Write-Banner "SECTION 6: Background Apps andServices - Moderate Cleanup"

    # Disable background apps globally (Windows 11)
    Write-Step "Disabling background apps globally..."
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" "GlobalUserDisabled" 1
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsRunInBackground" 2
    Write-Done "Background apps disabled globally"

    # Disable SysMain (Superfetch)
    Write-Step "Disabling SysMain (Superfetch)..."
    Disable-ServiceSafe "SysMain"

    # Disable unnecessary services
    Write-Step "Disabling unnecessary services..."

    $disableServices = @(
        "RemoteRegistry"     # Remote Registry
        "TermService"        # Remote Desktop Services
        "SessionEnv"         # Remote Desktop Configuration
        "UmRdpService"       # Remote Desktop Services UserMode Port Redirector
        "Fax"                # Fax
        "MapsBroker"         # Downloaded Maps Manager
        "lfsvc"              # Geolocation Service
        "RetailDemo"         # Retail Demo Service
        "wisvc"              # Windows Insider Service
        "WerSvc"             # Windows Error Reporting
    )

    foreach ($svc in $disableServices) {
        Disable-ServiceSafe $svc
    }

    Write-Host "`n  [i] Bluetooth, Printing, WSL/Hyper-V, audio, networking, GPU services are UNTOUCHED." -ForegroundColor Cyan
}

# ============================================================================
# SECTION 7: Start Menu, Taskbar andExplorer - Full Cleanup
# ============================================================================

function Invoke-ShellCleanup {
    Write-Banner "SECTION 7: Start Menu, Taskbar andExplorer - Full Cleanup"

    $contentPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    $explorerAdv = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"

    # Disable Start menu suggestions / recommendations
    Write-Step "Disabling Start menu suggestions and ads..."
    $subscribedKeys = @(
        "SubscribedContent-310093Enabled"   # Suggested apps in Start
        "SubscribedContent-314563Enabled"   # My People suggestions
        "SubscribedContent-338387Enabled"   # Start suggestion notifications
        "SubscribedContent-338388Enabled"   # Start suggested apps
        "SubscribedContent-338389Enabled"   # Start tips
        "SubscribedContent-338393Enabled"   # Settings suggestions
        "SubscribedContent-353694Enabled"   # Suggested content in Settings
        "SubscribedContent-353696Enabled"   # Suggested content in Settings
        "SubscribedContent-353698Enabled"   # Timeline suggestions
    )
    foreach ($key in $subscribedKeys) {
        Set-RegistryValue $contentPath $key 0
    }
    Set-RegistryValue $contentPath "SilentInstalledAppsEnabled" 0
    Set-RegistryValue $contentPath "SystemPaneSuggestionsEnabled" 0
    Set-RegistryValue $contentPath "SoftLandingEnabled" 0
    Set-RegistryValue $contentPath "RotatingLockScreenEnabled" 0
    Set-RegistryValue $contentPath "RotatingLockScreenOverlayEnabled" 0
    Write-Done "Start menu suggestions and ads disabled"

    # Hide Widgets from taskbar
    Write-Step "Hiding Widgets from taskbar..."
    Set-RegistryValue $explorerAdv "TaskbarDa" 0
    Write-Done "Widgets hidden"

    # Hide Chat from taskbar
    Write-Step "Hiding Chat from taskbar..."
    Set-RegistryValue $explorerAdv "TaskbarMn" 0
    Write-Done "Chat hidden"

    # Hide Copilot from taskbar
    Write-Step "Hiding Copilot from taskbar..."
    Set-RegistryValue $explorerAdv "ShowCopilotButton" 0
    Set-RegistryValue "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" "TurnOffWindowsCopilot" 1
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" "TurnOffWindowsCopilot" 1
    Write-Done "Copilot hidden and disabled"

    # Hide Task View button
    Write-Step "Hiding Task View button..."
    Set-RegistryValue $explorerAdv "ShowTaskViewButton" 0
    Write-Done "Task View button hidden"

    # Disable News and Interests
    Write-Step "Disabling News and Interests..."
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" "AllowNewsAndInterests" 0
    Write-Done "News and Interests disabled"

    # Restore classic right-click context menu
    Write-Step "Restoring classic right-click context menu..."
    $clsid = "HKCU:\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
    if (-not (Test-Path $clsid)) {
        New-Item -Path $clsid -Force | Out-Null
    }
    Set-ItemProperty -Path $clsid -Name "(Default)" -Value "" -Force
    Write-Done "Classic context menu restored (takes effect after Explorer restart)"

    # Disable lock screen tips and tricks
    Write-Step "Disabling lock screen tips..."
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338387Enabled" 0
    Set-RegistryValue "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1
    Write-Done "Lock screen tips disabled"

    # Disable Settings app suggestions
    Write-Step "Disabling Settings suggestions..."
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableCloudOptimizedContent" 1
    Write-Done "Settings suggestions disabled"
}

# ============================================================================
# SECTION 8: Network Optimization
# ============================================================================

function Invoke-NetworkOptimize {
    Write-Banner "SECTION 8: Network Optimization (Gaming)"

    $tcpipParams = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $tcpipInterfaces = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"

    # Disable Nagle's Algorithm (reduces latency in games)
    Write-Step "Disabling Nagle's Algorithm..."
    Set-RegistryValue $tcpipParams "TcpAckFrequency" 1
    Set-RegistryValue $tcpipParams "TCPNoDelay" 1

    # Apply Nagle disable to all network interfaces
    $interfaces = Get-ChildItem $tcpipInterfaces -ErrorAction SilentlyContinue
    foreach ($iface in $interfaces) {
        Set-RegistryValue $iface.PSPath "TcpAckFrequency" 1
        Set-RegistryValue $iface.PSPath "TCPNoDelay" 1
    }
    Write-Done "Nagle's Algorithm disabled on all interfaces"

    # Disable Network Throttling Index
    Write-Step "Disabling network throttling..."
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "NetworkThrottlingIndex" 0xffffffff
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "SystemResponsiveness" 0
    Write-Done "Network throttling disabled"

    # Faster socket recycling
    Write-Step "Setting faster socket recycling (TcpTimedWaitDelay = 30)..."
    Set-RegistryValue $tcpipParams "TcpTimedWaitDelay" 30
    Write-Done "Socket recycling optimized"

    # Disable Wi-Fi Sense
    Write-Step "Disabling Wi-Fi Sense..."
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" "AutoConnectAllowedOEM" 0
    Write-Done "Wi-Fi Sense disabled"

    # Disable QoS reserved bandwidth
    Write-Step "Removing QoS reserved bandwidth limit..."
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" "NonBestEffortLimit" 0
    Write-Done "QoS reserved bandwidth set to 0"

    # Disable Large Send Offload (can cause latency spikes)
    Write-Step "Disabling Large Send Offload v2..."
    $adapters = Get-NetAdapterAdvancedProperty -DisplayName "Large Send Offload*" -ErrorAction SilentlyContinue
    foreach ($adapter in $adapters) {
        Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName $adapter.DisplayName -DisplayValue "Disabled" -ErrorAction SilentlyContinue
    }
    Write-Done "Large Send Offload disabled (where applicable)"

    # Gaming-specific: prioritize games in multimedia scheduler
    Write-Step "Configuring Multimedia Scheduler for gaming..."
    $mmcssPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"
    Set-RegistryValue $mmcssPath "GPU Priority" 8
    Set-RegistryValue $mmcssPath "Priority" 6
    Set-RegistryValue $mmcssPath "Scheduling Category" "High" "String"
    Set-RegistryValue $mmcssPath "SFIO Priority" "High" "String"
    Write-Done "Multimedia Scheduler optimized for gaming"
}

# ============================================================================
# SECTION 9: Power Plan - High Performance
# ============================================================================

function Invoke-PowerPlanOptimize {
    Write-Banner "SECTION 9: Power Plan - High Performance"

    # Activate High Performance plan
    Write-Step "Activating High Performance power plan..."
    powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2>$null

    # Verify
    $activePlan = powercfg /getactivescheme 2>$null
    if ($activePlan -match "High performance") {
        Write-Done "High Performance power plan activated"
    }
    else {
        # Plan might not exist; duplicate from balanced and configure
        Write-Host "  [!] High Performance plan not found, creating one..." -ForegroundColor Yellow
        $guid = (powercfg /duplicatescheme 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2>$null) -replace '.*\s([a-f0-9-]{36}).*', '$1'
        if ($guid) {
            powercfg /setactive $guid 2>$null
            Write-Done "Created and activated High Performance plan"
        }
        else {
            # Last resort: use Ultimate Performance
            powercfg /setactive e9a42b02-d5df-448d-aa00-03f14749eb61 2>$null
            $check = powercfg /getactivescheme 2>$null
            if ($check -match "Ultimate") {
                Write-Done "Ultimate Performance plan activated (fallback)"
            }
            else {
                Write-Host "  [!] Could not activate High Performance plan. Check manually." -ForegroundColor Red
            }
        }
    }

    # Disable USB Selective Suspend
    Write-Step "Disabling USB Selective Suspend..."
    # GUID: 2a737441-1930-4402-8d77-b2bebba308a3 / 48e6b7a6-50f5-4782-a5d4-53bb8f07e226
    powercfg /setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
    powercfg /setdcvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
    Write-Done "USB Selective Suspend disabled"

    # Disable hard disk sleep (set to 0 = never)
    Write-Step "Disabling hard disk sleep timeout..."
    powercfg /change disk-timeout-ac 0
    powercfg /change disk-timeout-dc 0
    Write-Done "Hard disk sleep timeout disabled"

    # Disable monitor/screen timeout (0 = never turn off)
    Write-Step "Disabling screen timeout (monitor never turns off)..."
    powercfg /change monitor-timeout-ac 0
    powercfg /change monitor-timeout-dc 0
    Write-Done "Screen timeout disabled"

    # Disable system sleep / standby (0 = never sleep)
    Write-Step "Disabling system sleep (PC never goes to standby)..."
    powercfg /change standby-timeout-ac 0
    powercfg /change standby-timeout-dc 0
    Write-Done "System sleep disabled"

    # Disable hibernate
    Write-Step "Disabling hibernate..."
    powercfg /change hibernate-timeout-ac 0
    powercfg /change hibernate-timeout-dc 0
    powercfg /hibernate off
    Write-Done "Hibernate disabled (also frees disk space from hiberfil.sys)"

    # Apply changes
    powercfg /setactive scheme_current 2>$null
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "  ║       Windows 11 Custom Debloat andOptimization Script       ║" -ForegroundColor Magenta
Write-Host "  ║       Gaming + Dev + Browsing - Kill Telemetry Edition      ║" -ForegroundColor Magenta
Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host ""
Write-Host "  This script will:" -ForegroundColor White
Write-Host "    1. Create a restore point and registry backups" -ForegroundColor Gray
Write-Host "    2. Kill all telemetry" -ForegroundColor Gray
Write-Host "    3. Remove bloatware (keeping Store, Xbox, Calculator, Photos, Terminal)" -ForegroundColor Gray
Write-Host "    4. Disable Search/Cortana" -ForegroundColor Gray
Write-Host "    5. Disable SmartScreen (keep Defender)" -ForegroundColor Gray
Write-Host "    6. Optimize visual effects (balanced)" -ForegroundColor Gray
Write-Host "    7. Clean up background apps and services" -ForegroundColor Gray
Write-Host "    8. Clean up taskbar and Explorer (no ads/Widgets/Chat/Copilot)" -ForegroundColor Gray
Write-Host "    9. Optimize network for gaming" -ForegroundColor Gray
Write-Host "   10. Set High Performance power plan" -ForegroundColor Gray
Write-Host ""
Write-Host "  Press any key to start, or Ctrl+C to cancel..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

Invoke-SafetyBackup
Invoke-TelemetryKill
Invoke-BloatwareRemoval
Invoke-SearchCortanaDisable
Invoke-SmartScreenDisable
Invoke-VisualEffectsOptimize
Invoke-BackgroundCleanup
Invoke-ShellCleanup
Invoke-NetworkOptimize
Invoke-PowerPlanOptimize

$stopwatch.Stop()

# Restart Explorer to apply shell changes
Write-Banner "Finalizing"
Write-Step "Restarting Explorer to apply UI changes..."
Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Start-Process explorer

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║                    DEBLOAT COMPLETE!                        ║" -ForegroundColor Green
Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
$elapsed = '{0:mm}:{0:ss}' -f $stopwatch.Elapsed
Write-Host "  Elapsed time: $elapsed" -ForegroundColor Cyan
Write-Host ""
Write-Host "  What was done:" -ForegroundColor White
Write-Host "    - Restore point created + registry backed up to .\registry-backup\" -ForegroundColor Gray
Write-Host "    - All telemetry killed (services, tasks, registry)" -ForegroundColor Gray
Write-Host "    - Bloatware removed (kept Store, Xbox, Calculator, Photos, Terminal)" -ForegroundColor Gray
Write-Host "    - Search/Cortana disabled" -ForegroundColor Gray
Write-Host "    - SmartScreen disabled (Defender untouched)" -ForegroundColor Gray
Write-Host "    - Visual effects balanced" -ForegroundColor Gray
Write-Host "    - Background apps/services cleaned up" -ForegroundColor Gray
Write-Host "    - Taskbar cleaned (no Widgets/Chat/Copilot/TaskView)" -ForegroundColor Gray
Write-Host "    - Classic right-click context menu restored" -ForegroundColor Gray
Write-Host "    - Network optimized for gaming (Nagle off, throttling off)" -ForegroundColor Gray
Write-Host "    - High Performance power plan active (no sleep, no screen timeout)" -ForegroundColor Gray
Write-Host ""
Write-Host "  [!] A REBOOT is recommended to apply all changes." -ForegroundColor Yellow
Write-Host ""
Write-Host "  To undo: Use System Restore from the restore point created above," -ForegroundColor DarkGray
Write-Host "  or import the .reg files from .\registry-backup\" -ForegroundColor DarkGray
Write-Host ""
