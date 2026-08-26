[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$InstallerPath,
  [string]$InstallDir = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($InstallDir)) {
  $InstallDir = Join-Path $repoRoot 'target\microclaw-work-windows-installer\smoke-install'
}
$InstallerPath = [System.IO.Path]::GetFullPath($InstallerPath)
$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)
$expectedRoot = [System.IO.Path]::GetFullPath((Join-Path $repoRoot 'target\microclaw-work-windows-installer'))
if (-not $InstallDir.StartsWith($expectedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
  throw "Refusing to use smoke install directory outside $expectedRoot"
}
if (-not (Test-Path $InstallerPath)) { throw "Installer not found: $InstallerPath" }
if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }

$process = $null
try {
  $install = Start-Process -FilePath $InstallerPath -ArgumentList @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-', "/DIR=`"$InstallDir`"") -Wait -PassThru
  if ($install.ExitCode -ne 0) { throw "Silent installer exited with $($install.ExitCode)" }
  $binary = Join-Path $InstallDir 'microclaw-work.exe'
  if (-not (Test-Path $binary)) { throw "Installed application not found: $binary" }

  $process = Start-Process -FilePath $binary -PassThru
  Start-Sleep -Seconds 3
  if ($process.HasExited) { throw "Installed MicroClaw Work exited during launch smoke with $($process.ExitCode)" }
  Stop-Process -Id $process.Id -Force
  $process.WaitForExit()
  $process = $null

  $uninstaller = Join-Path $InstallDir 'unins000.exe'
  if (-not (Test-Path $uninstaller)) { throw "Uninstaller not found: $uninstaller" }
  $uninstall = Start-Process -FilePath $uninstaller -ArgumentList @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART') -Wait -PassThru
  if ($uninstall.ExitCode -ne 0) { throw "Silent uninstaller exited with $($uninstall.ExitCode)" }
  Write-Host 'MicroClaw Work Windows installer smoke passed'
}
finally {
  if ($null -ne $process -and -not $process.HasExited) { Stop-Process -Id $process.Id -Force }
}
