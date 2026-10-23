# Vardr – instalacja i aktualizacja Sysmona (Sysinternals) na komputerze.
# Do uruchamiania jako skrypt startowy komputera w GPO (konto SYSTEM) albo
# ręcznie jako administrator. Można uruchamiać wielokrotnie:
#   - brak Sysmona            -> instalacja z konfiguracją,
#   - starsza wersja          -> aktualizacja programu,
#   - inna konfiguracja       -> wczytanie nowej konfiguracji (sysmon -c),
#   - wszystko aktualne       -> nic.
# Agent Vardr NIE instaluje Sysmona sam – tylko raportuje jego stan,
# a panel (grupa z opcją „Wymagany Sysmon”) wskazuje komputery bez niego.
#
# Źródło plików (zalecane w firmie): udział sieciowy z Sysmon64.exe
# i sysmonconfig.xml, np.
#   powershell -ExecutionPolicy Bypass -File sysmon.ps1 -Source \\azujo.centrala\NETLOGON\sysmon
# Bez -Source skrypt pobiera Sysmona od Microsoftu, a konfigurację z -ConfigUrl
# (domyślnie SwiftOnSecurity). Przed uruchomieniem sprawdzany jest podpis
# Microsoftu. Uruchomienie oznacza akceptację licencji Sysinternals (-accepteula).
param(
    [string]$Source = "",
    [string]$ConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml",
    [string]$LogFile = "$env:ProgramData\SiemAgent\sysmon-setup.log"
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Log($msg) {
    $line = "$(Get-Date -Format s) $msg"
    Write-Host $line
    try {
        New-Item -ItemType Directory -Force -Path (Split-Path $LogFile) | Out-Null
        Add-Content -Path $LogFile -Value $line
    } catch { }
}

$work = Join-Path $env:TEMP "vardr-sysmon-$(Get-Random)"
New-Item -ItemType Directory -Force -Path $work | Out-Null
try {
    if ($Source) {
        Copy-Item (Join-Path $Source "Sysmon64.exe") $work
        Copy-Item (Join-Path $Source "sysmonconfig.xml") $work
    } else {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$work\Sysmon.zip" -UseBasicParsing
        Expand-Archive "$work\Sysmon.zip" $work -Force
        Invoke-WebRequest $ConfigUrl -OutFile "$work\sysmonconfig.xml" -UseBasicParsing
    }
    $exe = Join-Path $work "Sysmon64.exe"
    $cfg = Join-Path $work "sysmonconfig.xml"

    # Tylko program podpisany przez Microsoft.
    $sig = Get-AuthenticodeSignature $exe
    if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch "O=Microsoft Corporation") {
        throw "Sysmon64.exe without a valid Microsoft signature ($($sig.Status)) – aborted"
    }
    [xml](Get-Content $cfg -Raw) | Out-Null   # konfiguracja musi być poprawnym XML

    $newVer = [version](Get-Item $exe).VersionInfo.FileVersion
    $svc = Get-Service Sysmon64, Sysmon -ErrorAction SilentlyContinue | Select-Object -First 1
    $cfgHash = (Get-FileHash $cfg).Hash
    $stamp = "$env:ProgramData\SiemAgent\sysmon-config.sha256"

    if (-not $svc) {
        & $exe -accepteula -i $cfg | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Sysmon installation failed (code $LASTEXITCODE)" }
        Set-Content $stamp $cfgHash
        Log "installed Sysmon $newVer with configuration $($cfgHash.Substring(0,12))"
        return
    }
    $installed = (Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'").PathName.Trim('"')
    $curVer = [version](Get-Item $installed).VersionInfo.FileVersion
    if ($newVer -gt $curVer) {
        & $installed -u | Out-Null
        & $exe -accepteula -i $cfg | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Sysmon upgrade failed (code $LASTEXITCODE)" }
        Set-Content $stamp $cfgHash
        Log "upgraded Sysmon $curVer -> $newVer"
        return
    }
    $prev = if (Test-Path $stamp) { (Get-Content $stamp -Raw).Trim() } else { "" }
    if ($prev -ne $cfgHash) {
        & $installed -c $cfg | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "loading the Sysmon configuration failed (code $LASTEXITCODE)" }
        Set-Content $stamp $cfgHash
        Log "loaded a new Sysmon configuration $($cfgHash.Substring(0,12))"
        return
    }
    if ($svc.Status -ne "Running") {
        Start-Service $svc.Name
        Log "started the stopped service $($svc.Name)"
        return
    }
    Log "Sysmon $curVer up to date, configuration unchanged"
} catch {
    Log "ERROR: $_"
    exit 1
} finally {
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}
