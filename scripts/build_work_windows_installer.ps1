[CmdletBinding()]
param(
  [string]$InnoSetupCompilerPath = '',
  [ValidateSet('work-release', 'release', 'debug')]
  [string]$Configuration = 'work-release',
  [string]$StageDir = '',
  [string]$OutputDir = '',
  [string]$OutputBaseFilename = '',
  [string]$CodeSigningCertificateSha1 = '',
  [string]$SignToolPath = '',
  [string]$TimestampUrl = 'http://timestamp.digicert.com',
  [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-PackageVersion([string]$CargoTomlPath) {
  $inPackage = $false
  foreach ($line in Get-Content $CargoTomlPath) {
    if ($line -match '^\s*\[package\]\s*$') { $inPackage = $true; continue }
    if ($inPackage -and $line -match '^\s*\[') { break }
    if ($inPackage -and $line -match '^\s*version\s*=\s*"([^"]+)"\s*$') { return $Matches[1] }
  }
  throw "Could not determine package version from $CargoTomlPath"
}

function Resolve-InnoCompiler([string]$RequestedPath) {
  $candidates = @()
  if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) { $candidates += $RequestedPath }
  $command = Get-Command ISCC.exe -ErrorAction SilentlyContinue
  if ($null -ne $command) { $candidates += $command.Source }
  $candidates += @(
    (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'),
    (Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe')
  )
  foreach ($candidate in $candidates) {
    if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path $candidate)) {
      return (Resolve-Path $candidate).Path
    }
  }
  throw 'Inno Setup 6 compiler not found. Install it or pass -InnoSetupCompilerPath.'
}

function Resolve-SignTool([string]$RequestedPath) {
  if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) {
    if (-not (Test-Path $RequestedPath)) { throw "SignTool not found: $RequestedPath" }
    return (Resolve-Path $RequestedPath).Path
  }
  $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
  if ($null -ne $command) { return $command.Source }
  $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
  $candidate = Get-ChildItem $kits -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
    Sort-Object FullName -Descending |
    Select-Object -First 1
  if ($null -eq $candidate) { throw 'SignTool not found. Install the Windows SDK or pass -SignToolPath.' }
  return $candidate.FullName
}

function Invoke-CodeSign([string]$Path, [string]$CertificateSha1, [string]$Tool, [string]$Timestamp) {
  & $Tool sign /sha1 $CertificateSha1 /fd SHA256 /tr $Timestamp /td SHA256 $Path
  if ($LASTEXITCODE -ne 0) { throw "Code signing failed for $Path" }
  & $Tool verify /pa /v $Path
  if ($LASTEXITCODE -ne 0) { throw "Signature verification failed for $Path" }
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$cargoToml = Join-Path $repoRoot 'apps\microclaw-work\Cargo.toml'
$version = Get-PackageVersion $cargoToml
$issPath = Join-Path $repoRoot 'packaging\microclaw-work\windows\microclaw-work.iss'
$iconPath = Join-Path $repoRoot 'packaging\microclaw-work\windows\MicroClawWork.ico'
if ([string]::IsNullOrWhiteSpace($StageDir)) { $StageDir = Join-Path $repoRoot 'target\microclaw-work-windows-installer\app' }
if ([string]::IsNullOrWhiteSpace($OutputDir)) { $OutputDir = Join-Path $repoRoot 'target\microclaw-work-windows-installer\out' }
if ([string]::IsNullOrWhiteSpace($OutputBaseFilename)) { $OutputBaseFilename = "MicroClaw-Work-$version-windows-x64-setup" }

if (-not $SkipBuild) {
  $cargoArgs = @('build', '-p', 'microclaw-work', '--locked')
  if ($Configuration -eq 'release') { $cargoArgs += '--release' }
  if ($Configuration -eq 'work-release') { $cargoArgs += @('--profile', 'work-release') }
  & cargo @cargoArgs
  if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE" }
}

$binaryPath = Join-Path $repoRoot "target\$Configuration\microclaw-work.exe"
if (-not (Test-Path $binaryPath)) { throw "Built binary not found: $binaryPath" }
if (Test-Path $StageDir) { Remove-Item $StageDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $StageDir, $OutputDir | Out-Null
Copy-Item $binaryPath (Join-Path $StageDir 'microclaw-work.exe') -Force
Copy-Item (Join-Path $repoRoot 'LICENSE') (Join-Path $StageDir 'LICENSE.txt') -Force
Copy-Item (Join-Path $repoRoot 'apps\microclaw-work\README.md') (Join-Path $StageDir 'README.md') -Force

$signTool = ''
if (-not [string]::IsNullOrWhiteSpace($CodeSigningCertificateSha1)) {
  $signTool = Resolve-SignTool $SignToolPath
  Invoke-CodeSign (Join-Path $StageDir 'microclaw-work.exe') $CodeSigningCertificateSha1 $signTool $TimestampUrl
}

$compiler = Resolve-InnoCompiler $InnoSetupCompilerPath
& $compiler "/DAppVersion=$version" "/DSourceDir=$StageDir" "/DOutputDir=$OutputDir" "/DOutputBaseFilename=$OutputBaseFilename" "/DIconFile=$iconPath" $issPath
if ($LASTEXITCODE -ne 0) { throw "Inno Setup compilation failed with exit code $LASTEXITCODE" }

$installer = Join-Path $OutputDir ($OutputBaseFilename + '.exe')
if (-not (Test-Path $installer)) { throw "Installer output not found: $installer" }
if (-not [string]::IsNullOrWhiteSpace($CodeSigningCertificateSha1)) {
  Invoke-CodeSign $installer $CodeSigningCertificateSha1 $signTool $TimestampUrl
}
Write-Host $installer
