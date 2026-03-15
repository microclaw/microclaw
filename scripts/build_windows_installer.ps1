[CmdletBinding()]
param(
  [string]$InnoSetupCompilerPath = 'D:\Program Files (x86)\Inno Setup 6\Compil32.exe',
  [ValidateSet('release', 'debug')]
  [string]$Configuration = 'release',
  [string]$Target = '',
  [string[]]$Features = @(),
  [string]$StageDir = '',
  [string]$OutputDir = '',
  [string]$OutputBaseFilename = '',
  [switch]$SkipBuild,
  [switch]$UseCompil32
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-PackageVersion {
  param(
    [Parameter(Mandatory = $true)]
    [string]$CargoTomlPath
  )

  $inPackageSection = $false
  foreach ($line in Get-Content $CargoTomlPath) {
    if ($line -match '^\s*\[package\]\s*$') {
      $inPackageSection = $true
      continue
    }

    if ($inPackageSection -and $line -match '^\s*\[') {
      break
    }

    if ($inPackageSection -and $line -match '^\s*version\s*=\s*"([^"]+)"\s*$') {
      return $Matches[1]
    }
  }

  throw "Could not determine package version from $CargoTomlPath"
}

function Get-AppArchitecture {
  param(
    [string]$TargetTriple
  )

  if (-not [string]::IsNullOrWhiteSpace($TargetTriple)) {
    if ($TargetTriple -match '^x86_64-') {
      return 'x64'
    }

    if ($TargetTriple -match '^aarch64-') {
      return 'arm64'
    }

    throw "Unsupported target triple for installer: $TargetTriple"
  }

  switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture) {
    'X64' { return 'x64' }
    'Arm64' { return 'arm64' }
    default { throw "Unsupported host architecture: $([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture)" }
  }
}

function Get-InstallerArchitectureSettings {
  param(
    [Parameter(Mandatory = $true)]
    [string]$AppArchitecture
  )

  switch ($AppArchitecture) {
    'x64' {
      return @{
        ArchitecturesAllowed = 'x64compatible'
        ArchitecturesInstallIn64BitMode = 'x64compatible'
      }
    }
    'arm64' {
      return @{
        ArchitecturesAllowed = 'arm64'
        ArchitecturesInstallIn64BitMode = 'arm64'
      }
    }
    default {
      throw "Unsupported installer architecture: $AppArchitecture"
    }
  }
}

function Resolve-InnoCompiler {
  param(
    [Parameter(Mandatory = $true)]
    [string]$RequestedCompilerPath,
    [switch]$PreferCompil32
  )

  if (-not (Test-Path $RequestedCompilerPath)) {
    throw "Inno Setup compiler not found: $RequestedCompilerPath"
  }

  $resolvedPath = (Resolve-Path $RequestedCompilerPath).Path
  if ($PreferCompil32) {
    return $resolvedPath
  }

  $compilerName = [System.IO.Path]::GetFileName($resolvedPath)
  if ($compilerName -ieq 'Compil32.exe') {
    $isccPath = Join-Path (Split-Path -Parent $resolvedPath) 'ISCC.exe'
    if (Test-Path $isccPath) {
      return (Resolve-Path $isccPath).Path
    }
  }

  return $resolvedPath
}

function Copy-Artifact {
  param(
    [Parameter(Mandatory = $true)]
    [string]$SourcePath,
    [Parameter(Mandatory = $true)]
    [string]$DestinationPath
  )

  if (-not (Test-Path $SourcePath)) {
    throw "Required file not found: $SourcePath"
  }

  Copy-Item -Path $SourcePath -Destination $DestinationPath -Force
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$issPath = Join-Path $repoRoot 'packaging\windows\microclaw.iss'
$cargoTomlPath = Join-Path $repoRoot 'Cargo.toml'
$version = Get-PackageVersion -CargoTomlPath $cargoTomlPath
$appArchitecture = Get-AppArchitecture -TargetTriple $Target
$archSettings = Get-InstallerArchitectureSettings -AppArchitecture $appArchitecture

if ([string]::IsNullOrWhiteSpace($StageDir)) {
  $StageDir = Join-Path $repoRoot 'target\windows-installer\app'
}
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
  $OutputDir = Join-Path $repoRoot 'target\windows-installer\out'
}
$StageDir = [System.IO.Path]::GetFullPath($StageDir)
$OutputDir = [System.IO.Path]::GetFullPath($OutputDir)
if ([string]::IsNullOrWhiteSpace($OutputBaseFilename)) {
  $OutputBaseFilename = "microclaw-$version-$appArchitecture-setup"
}

$binaryPath = if ([string]::IsNullOrWhiteSpace($Target)) {
  Join-Path $repoRoot "target\$Configuration\microclaw.exe"
} else {
  Join-Path $repoRoot "target\$Target\$Configuration\microclaw.exe"
}

if (-not $SkipBuild) {
  $cargoArgs = @('build', '--locked')
  if ($Configuration -eq 'release') {
    $cargoArgs += '--release'
  }
  if (-not [string]::IsNullOrWhiteSpace($Target)) {
    $cargoArgs += @('--target', $Target)
  }
  if ($Features.Count -gt 0) {
    $cargoArgs += @('--features', ($Features -join ','))
  }

  Write-Host "Building microclaw.exe with cargo $($cargoArgs -join ' ')"
  & cargo @cargoArgs
  if ($LASTEXITCODE -ne 0) {
    throw "cargo build failed with exit code $LASTEXITCODE"
  }
}

if (-not (Test-Path $binaryPath)) {
  throw "Built binary not found: $binaryPath"
}

if (Test-Path $StageDir) {
  Remove-Item -Path $StageDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $StageDir | Out-Null
$examplesDir = Join-Path $StageDir 'examples'
New-Item -ItemType Directory -Force -Path $examplesDir | Out-Null
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

Copy-Artifact -SourcePath $binaryPath -DestinationPath (Join-Path $StageDir 'microclaw.exe')
Copy-Artifact -SourcePath (Join-Path $repoRoot 'LICENSE') -DestinationPath (Join-Path $StageDir 'LICENSE.txt')
Copy-Artifact -SourcePath (Join-Path $repoRoot 'README.md') -DestinationPath (Join-Path $StageDir 'README.md')
Copy-Artifact -SourcePath (Join-Path $repoRoot 'README_CN.md') -DestinationPath (Join-Path $StageDir 'README_CN.md')
Copy-Artifact -SourcePath (Join-Path $repoRoot 'microclaw.config.example.yaml') -DestinationPath (Join-Path $examplesDir 'microclaw.config.example.yaml')

Get-ChildItem -Path $repoRoot -Filter 'mcp*.example.json' | ForEach-Object {
  Copy-Artifact -SourcePath $_.FullName -DestinationPath (Join-Path $examplesDir $_.Name)
}

$compilerPath = Resolve-InnoCompiler -RequestedCompilerPath $InnoSetupCompilerPath -PreferCompil32:$UseCompil32
$compilerName = [System.IO.Path]::GetFileName($compilerPath)
$compilerArgs = @()
if ($compilerName -ieq 'Compil32.exe') {
  $compilerArgs += '/cc'
}
$compilerArgs += @(
  "/DAppVersion=$version",
  "/DSourceDir=$StageDir",
  "/DOutputDir=$OutputDir",
  "/DOutputBaseFilename=$OutputBaseFilename",
  "/DArchitecturesAllowed=$($archSettings.ArchitecturesAllowed)",
  "/DArchitecturesInstallIn64BitMode=$($archSettings.ArchitecturesInstallIn64BitMode)",
  $issPath
)

Write-Host "Compiling installer with $compilerPath"
& $compilerPath @compilerArgs
if ($LASTEXITCODE -ne 0) {
  throw "Inno Setup compilation failed with exit code $LASTEXITCODE"
}

$setupPath = Join-Path $OutputDir ($OutputBaseFilename + '.exe')
if (-not (Test-Path $setupPath)) {
  throw "Installer output not found: $setupPath"
}

Write-Host "Installer created:"
Write-Host $setupPath
