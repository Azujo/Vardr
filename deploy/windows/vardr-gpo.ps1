# Vardr – polityka audytu Windows w GPO (roadmapa, załącznik B; README,
# sekcja „Polityka audytu”). Uruchom na kontrolerze domeny jako administrator
# domeny. Skrypt można uruchamiać wielokrotnie – aktualizuje istniejące GPO.
#
# Tworzy i podłącza:
#   „Vardr - polityka audytu” (cała domena):
#     - zaawansowana polityka inspekcji (audit.csv) – logowania, Kerberos,
#       konta i grupy, tworzenie procesów, zmiany polityk, usługi;
#     - linia poleceń w zdarzeniu 4688, logowanie bloków skryptów PowerShell (4104),
#     - wymuszenie podkategorii inspekcji (zastępuje starą politykę),
#     - dziennik Security 256 MB, PowerShell/Operational 64 MB;
#   „Vardr - dzienniki DC” (OU Domain Controllers): dziennik Security 1 GB.
#
# Po zmianie: gpupdate /force na komputerach (albo do 90 minut).
#Requires -Modules GroupPolicy, ActiveDirectory
$ErrorActionPreference = "Stop"

$domain = Get-ADDomain
$domainDN = $domain.DistinguishedName
$sysvol = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies"

function Ensure-Gpo($name, $target, $comment, $legacy) {
    $g = Get-GPO -Name $name -ErrorAction SilentlyContinue
    # GPO utworzone przed zmianą nazwy projektu (Heimdall -> Vardr): zmiana nazwy zamiast drugiego GPO.
    if (-not $g -and $legacy) {
        $g = Get-GPO -Name $legacy -ErrorAction SilentlyContinue
        if ($g) {
            $g.DisplayName = $name
            $g.Description = $comment
            Write-Host "zmieniono nazwę GPO: $legacy -> $name"
        }
    }
    if (-not $g) {
        $g = New-GPO -Name $name -Comment $comment
        Write-Host "utworzono GPO: $name"
    }
    if (-not ((Get-GPInheritance -Target $target).GpoLinks.DisplayName -contains $name)) {
        New-GPLink -Guid $g.Id -Target $target -LinkEnabled Yes | Out-Null
        Write-Host "  podłączono do $target"
    }
    return $g
}

# ---- GPO dla całej domeny ----
$gpo = Ensure-Gpo "Vardr - polityka audytu" $domainDN "Polityka audytu dla agentów Vardr (deploy/windows/vardr-gpo.ps1)" "Heimdall - polityka audytu"
$key = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
Set-GPRegistryValue -Guid $gpo.Id -Key $key -ValueName ProcessCreationIncludeCmdLine_Enabled -Type DWord -Value 1 | Out-Null
Set-GPRegistryValue -Guid $gpo.Id -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -ValueName EnableScriptBlockLogging -Type DWord -Value 1 | Out-Null
Set-GPRegistryValue -Guid $gpo.Id -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName SCENoApplyLegacyAuditPolicy -Type DWord -Value 1 | Out-Null
Set-GPRegistryValue -Guid $gpo.Id -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -ValueName MaxSize -Type DWord -Value 262144 | Out-Null
Set-GPRegistryValue -Guid $gpo.Id -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Microsoft-Windows-PowerShell/Operational" `
    -ValueName MaxSize -Type DWord -Value 65536 | Out-Null

# Zaawansowana polityka inspekcji: 1 = sukces, 2 = porażka, 3 = oba.
$audit = @(
    @("Credential Validation",              "{0CCE923F-69AE-11D9-BED3-505054503030}", 3),
    @("Kerberos Authentication Service",    "{0CCE9242-69AE-11D9-BED3-505054503030}", 3),
    @("Kerberos Service Ticket Operations", "{0CCE9240-69AE-11D9-BED3-505054503030}", 3),
    @("Logon",                              "{0CCE9215-69AE-11D9-BED3-505054503030}", 3),
    @("Logoff",                             "{0CCE9216-69AE-11D9-BED3-505054503030}", 1),
    @("Account Lockout",                    "{0CCE9217-69AE-11D9-BED3-505054503030}", 3),
    @("Special Logon",                      "{0CCE921B-69AE-11D9-BED3-505054503030}", 1),
    @("Other Logon/Logoff Events",          "{0CCE921C-69AE-11D9-BED3-505054503030}", 3),
    @("User Account Management",            "{0CCE9235-69AE-11D9-BED3-505054503030}", 3),
    @("Computer Account Management",        "{0CCE9236-69AE-11D9-BED3-505054503030}", 1),
    @("Security Group Management",          "{0CCE9237-69AE-11D9-BED3-505054503030}", 3),
    @("Other Account Management Events",    "{0CCE923A-69AE-11D9-BED3-505054503030}", 1),
    @("Process Creation",                   "{0CCE922B-69AE-11D9-BED3-505054503030}", 1),
    @("Audit Policy Change",                "{0CCE922F-69AE-11D9-BED3-505054503030}", 3),
    @("Authentication Policy Change",       "{0CCE9230-69AE-11D9-BED3-505054503030}", 1),
    @("Security System Extension",          "{0CCE9211-69AE-11D9-BED3-505054503030}", 1),
    @("System Integrity",                   "{0CCE9212-69AE-11D9-BED3-505054503030}", 3),
    @("Security State Change",              "{0CCE9210-69AE-11D9-BED3-505054503030}", 1),
    @("Other System Events",                "{0CCE9214-69AE-11D9-BED3-505054503030}", 3),
    @("Directory Service Changes",          "{0CCE923C-69AE-11D9-BED3-505054503030}", 1),
    @("Directory Service Access",           "{0CCE923B-69AE-11D9-BED3-505054503030}", 1)
)
$names = @{1 = "Success"; 2 = "Failure"; 3 = "Success and Failure"}
$csv = @("Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value")
foreach ($a in $audit) { $csv += ",System,Audit $($a[0]),$($a[1]),$($names[$a[2]]),,$($a[2])" }
$auditDir = Join-Path $sysvol "{$($gpo.Id)}\Machine\Microsoft\Windows NT\Audit"
New-Item -ItemType Directory -Force -Path $auditDir | Out-Null
$csv | Set-Content -Path (Join-Path $auditDir "audit.csv") -Encoding ASCII

# Rozszerzenie inspekcji w GPO (bez tego klienci pominą audit.csv) i nowa wersja.
$gpoDN = "CN={$($gpo.Id)},CN=Policies,CN=System,$domainDN"
$obj = Get-ADObject $gpoDN -Properties gPCMachineExtensionNames, versionNumber
$ext = "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]" +
       "[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]"
$version = [int]$obj.versionNumber + 1
Set-ADObject $gpoDN -Replace @{gPCMachineExtensionNames = $ext; versionNumber = $version}
$ini = Join-Path $sysvol "{$($gpo.Id)}\GPT.INI"
"[General]`r`nVersion=$version`r`n" | Set-Content -Path $ini -Encoding ASCII
Write-Host "  audit.csv: $($audit.Count) podkategorii, wersja GPO $version"

# ---- Kontrolery domeny: większy dziennik Security ----
$dc = Ensure-Gpo "Vardr - dzienniki DC" $domain.DomainControllersContainer "Dziennik Security 1 GB na kontrolerach domeny (Vardr)" "Heimdall - dzienniki DC"
Set-GPRegistryValue -Guid $dc.Id -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -ValueName MaxSize -Type DWord -Value 1048576 | Out-Null
# Link OU Domain Controllers ma pierwszeństwo przed linkiem domeny.
Write-Host "gotowe – uruchom gpupdate /force na komputerach"
