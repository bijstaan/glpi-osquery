<#
.SYNOPSIS
    Install the GLPI osquery agent as a Windows service.

.DESCRIPTION
    Lays down the same versioned tree the self-updater maintains
    (versions\<v> plus a `current` junction), so an installed-from-archive agent
    and an updated-in-place agent are the identical layout. Anything else would
    mean the update path is only ever exercised on machines that have already
    updated once.

.EXAMPLE
    .\install.ps1 -Server https://glpi.example.com -Secret abc123
    .\install.ps1 -Server https://glpi.example.com -Secret abc123 -CaCert C:\ca.pem
    .\install.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [string] $Server,
    [string] $Secret,
    [string] $CaCert,
    [switch] $Uninstall,
    [string] $InstallRoot = "$env:ProgramFiles\GLPI osquery Agent"
)

$ErrorActionPreference = 'Stop'
$ServiceName = 'GLPIOsqueryAgent'

function Assert-Administrator {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This installer must run from an elevated PowerShell session: osqueryd needs administrative rights to read WMI, the registry and disk information.'
    }
}

Assert-Administrator

if ($Uninstall) {
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Write-Host '==> stopping and removing the service'
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $ServiceName | Out-Null
    }
    Remove-Item -Recurse -Force $InstallRoot -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force "$env:ProgramData\GLPIOsqueryAgent" -ErrorAction SilentlyContinue
    Write-Host 'Removed.'
    return
}

$here    = Split-Path -Parent $MyInvocation.MyCommand.Path
$version = (Get-Content (Join-Path $here 'VERSION') -ErrorAction SilentlyContinue) -join ''
if (-not $version) { $version = '0.0.0' }

Write-Host "==> installing version $version"

$versionDir = Join-Path $InstallRoot "versions\$version"
New-Item -ItemType Directory -Force -Path (Join-Path $versionDir 'bin') | Out-Null
Copy-Item (Join-Path $here 'bin\*') (Join-Path $versionDir 'bin') -Force

# osqueryd verifies TLS with OpenSSL, which reads no Windows certificate store
# and falls back to a compiled-in directory that does not exist here. Without
# this bundle it has no trust anchors at all and enrolment fails against a
# perfectly ordinary certificate, so the copy is not optional.
New-Item -ItemType Directory -Force -Path (Join-Path $versionDir 'certs') | Out-Null
Copy-Item (Join-Path $here 'certs\*') (Join-Path $versionDir 'certs') -Force
Set-Content -Path (Join-Path $versionDir 'VERSION') -Value $version

# A junction rather than a symlink: creating a symlink needs either developer
# mode or SeCreateSymbolicLinkPrivilege, which an installer cannot rely on,
# whereas a directory junction works for any administrator.
$current = Join-Path $InstallRoot 'current'
if (Test-Path $current) { cmd /c rmdir "$current" | Out-Null }
cmd /c mklink /J "$current" "$versionDir" | Out-Null

$agent = Join-Path $current 'bin\glpi-osquery-agent.exe'

New-Item -ItemType Directory -Force -Path "$env:ProgramData\GLPIOsqueryAgent\state" | Out-Null

if ($Server -and $Secret) {
    Write-Host '==> enrolling'
    $enrollArgs = @('install', '--server', $Server, '--secret', $Secret)
    if ($CaCert) { $enrollArgs += @('--ca-cert', $CaCert) }
    & $agent @enrollArgs
    if ($LASTEXITCODE -ne 0) { throw "Enrolment failed with exit code $LASTEXITCODE" }
}

$configPath = "$env:ProgramData\GLPIOsqueryAgent\agent.json"
if (-not (Test-Path $configPath)) {
    Write-Warning @"
Installed, but not enrolled. Run:
  & '$agent' install --server https://glpi.example.com --secret <secret>
then re-run this script to register the service.
"@
    return
}

Write-Host '==> registering the service'
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

# LocalSystem: osqueryd needs it for WMI and raw disk access.
New-Service -Name $ServiceName `
    -BinaryPathName "`"$agent`" run" `
    -DisplayName 'GLPI osquery agent' `
    -Description 'Reports inventory to GLPI and answers live queries, via a bundled osqueryd.' `
    -StartupType Automatic | Out-Null

# Restart on failure, and treat a deliberate exit as a restart too: the agent
# stops on purpose after staging an update so it comes back on the new version.
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null
sc.exe failureflag $ServiceName 1 | Out-Null

Start-Service -Name $ServiceName
Get-Service -Name $ServiceName | Format-List Name, Status, StartType

Write-Host @"

Installed. Useful commands:
  Get-Service $ServiceName
  Get-Content '$env:ProgramData\GLPIOsqueryAgent\state\logs\osqueryd.INFO' -Tail 20
  .\install.ps1 -Uninstall
"@
