$services = @('DiagTrack','dmwappushservice','WSearch','RemoteRegistry','TermService','MapsBroker','lfsvc','WerSvc','SysMain','wisvc')
foreach ($n in $services) {
    $s = Get-Service $n -ErrorAction SilentlyContinue
    if ($s) {
        $wmi = Get-CimInstance Win32_Service -Filter "Name='$n'" -ErrorAction SilentlyContinue
        Write-Host "$n : Status=$($s.Status), StartMode=$($wmi.StartMode)"
    } else {
        Write-Host "$n : not found"
    }
}

Write-Host ""
Write-Host "=== Classic Context Menu ===" -ForegroundColor Cyan
$path = "HKCU:\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
if (Test-Path $path) {
    $val = (Get-ItemProperty $path -Name "(Default)" -ErrorAction SilentlyContinue)."(Default)"
    Write-Host "Key exists, value='$val' (empty string = classic menu active)"
} else {
    Write-Host "Key does NOT exist"
}

Write-Host ""
Write-Host "=== SmartScreen ===" -ForegroundColor Cyan
$val = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name SmartScreenEnabled -ErrorAction SilentlyContinue).SmartScreenEnabled
Write-Host "SmartScreenEnabled = '$val'"
$pol = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name EnableSmartScreen -ErrorAction SilentlyContinue).EnableSmartScreen
Write-Host "Policy EnableSmartScreen = $pol"

Write-Host ""
Write-Host "=== SystemResponsiveness ===" -ForegroundColor Cyan
$val = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name SystemResponsiveness -ErrorAction SilentlyContinue).SystemResponsiveness
Write-Host "SystemResponsiveness = $val"
