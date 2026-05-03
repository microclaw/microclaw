param(
  [string]$Repo = $(if ($env:MICROCLAW_REPO) { $env:MICROCLAW_REPO } else { 'microclaw/microclaw' }),
  [string]$InstallDir = $(if ($env:MICROCLAW_INSTALL_DIR) { $env:MICROCLAW_INSTALL_DIR } else { Join-Path $env:USERPROFILE '.local\bin' }),
  [switch]$Full,
  [switch]$SkipRun,
  [int]$WaitForPid = 0
)

$ErrorActionPreference = 'Stop'
$BinName = 'microclaw.exe'
$Variant = if ($Full.IsPresent -or $env:MICROCLAW_VARIANT -eq 'full') { 'full' } else { 'default' }
$ApiUrl = "https://api.github.com/repos/$Repo/releases/latest"
$skipRunFromEnv = $false
if ($env:MICROCLAW_INSTALL_SKIP_RUN) {
  $skipRunFromEnv = @('1', 'true', 'yes') -contains $env:MICROCLAW_INSTALL_SKIP_RUN.Trim().ToLowerInvariant()
}
$skipRunEffective = $SkipRun.IsPresent -or $skipRunFromEnv
$hadExistingCommand = ($WaitForPid -gt 0) -or ($null -ne (Get-Command microclaw -ErrorAction SilentlyContinue))

function Write-Info([string]$msg) {
  Write-Host $msg
}

function Resolve-Arch {
  switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture) {
    'X64' { return 'x86_64' }
    'Arm64' { return 'aarch64' }
    default { throw "Unsupported architecture: $([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture)" }
  }
}

function Select-AssetUrl([object]$release, [string]$arch, [string]$variant) {
  if ($variant -eq 'full') {
    $prefix = 'microclaw-full'
  } else {
    $prefix = 'microclaw'
  }
  $patterns = @(
    "$prefix-[0-9]+\.[0-9]+\.[0-9]+-$arch-windows-msvc\.zip$",
    "$prefix-[0-9]+\.[0-9]+\.[0-9]+-.*$arch.*windows.*\.zip$"
  )

  foreach ($p in $patterns) {
    $match = $release.assets | Where-Object { $_.browser_download_url -match $p } | Select-Object -First 1
    if ($null -ne $match) {
      return $match.browser_download_url
    }
  }

  return $null
}

function Path-Contains([string]$pathValue, [string]$dir) {
  if ([string]::IsNullOrWhiteSpace($pathValue)) { return $false }
  $needle = $dir.Trim().TrimEnd('\\').ToLowerInvariant()
  foreach ($part in $pathValue.Split(';')) {
    if ([string]::IsNullOrWhiteSpace($part)) { continue }
    if ($part.Trim().TrimEnd('\\').ToLowerInvariant() -eq $needle) {
      return $true
    }
  }
  return $false
}

function Ensure-UserPathContains([string]$dir) {
  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (Path-Contains $userPath $dir) {
    return $false
  }

  $newPath = if ([string]::IsNullOrWhiteSpace($userPath)) {
    $dir
  } else {
    "$userPath;$dir"
  }

  [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')

  # Also update current process PATH so this shell can find it immediately.
  if (-not (Path-Contains $env:Path $dir)) {
    $env:Path = "$env:Path;$dir"
  }

  return $true
}

function Wait-ForProcessExit([int]$ProcessId) {
  if ($ProcessId -le 0) { return }

  try {
    $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if ($null -ne $process) {
      $process.WaitForExit()
    }
  } catch {
    Start-Sleep -Milliseconds 500
  }

  Start-Sleep -Seconds 1
}

$arch = Resolve-Arch
if ($Variant -eq 'full') {
  Write-Info "Installing microclaw (full variant) for windows/$arch..."
} else {
  Write-Info "Installing microclaw for windows/$arch..."
}

$release = Invoke-RestMethod -Uri $ApiUrl -Headers @{ 'User-Agent' = 'microclaw-install-script' }
$assetUrl = Select-AssetUrl -release $release -arch $arch -variant $Variant
if (-not $assetUrl) {
  throw "No prebuilt binary found for windows/$arch in the latest GitHub release."
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$tmpDir = New-Item -ItemType Directory -Force -Path (Join-Path ([System.IO.Path]::GetTempPath()) ("microclaw-install-" + [guid]::NewGuid().ToString()))
try {
  $archivePath = Join-Path $tmpDir.FullName 'microclaw.zip'
  Write-Info "Downloading: $assetUrl"
  Invoke-WebRequest -Uri $assetUrl -OutFile $archivePath

  Expand-Archive -Path $archivePath -DestinationPath $tmpDir.FullName -Force
  # Full variant archives contain "microclaw-full.exe"; fall back to "microclaw.exe".
  $bin = Get-ChildItem -Path $tmpDir.FullName -Filter 'microclaw-full.exe' -Recurse | Select-Object -First 1
  if (-not $bin) {
    $bin = Get-ChildItem -Path $tmpDir.FullName -Filter $BinName -Recurse | Select-Object -First 1
  }
  if (-not $bin) {
    throw "Could not find $BinName in archive"
  }

  $targetPath = Join-Path $InstallDir $BinName
  $stagedTargetPath = Join-Path $InstallDir ".$BinName.tmp.$PID"

  Wait-ForProcessExit -ProcessId $WaitForPid

  Copy-Item -Path $bin.FullName -Destination $stagedTargetPath -Force
  if (Test-Path $targetPath) {
    Remove-Item -Path $targetPath -Force
  }
  Move-Item -Path $stagedTargetPath -Destination $targetPath -Force

  $pathUpdated = Ensure-UserPathContains $InstallDir

  Write-Info "Installed microclaw to: $targetPath"
  if ($pathUpdated) {
    Write-Info "Added '$InstallDir' to your user PATH."
    Write-Info "Open a new terminal if command lookup does not refresh immediately."
  } else {
    Write-Info "PATH already contains '$InstallDir'."
  }

  Write-Info "microclaw"
  if ($skipRunEffective) {
    Write-Info "Skipping auto-run (-SkipRun)."
  } elseif ($hadExistingCommand) {
    Write-Info "Skipping auto-run (upgrade detected)."
  } elseif (Get-Command microclaw -ErrorAction SilentlyContinue) {
    Write-Info "Running: microclaw"
    try {
      & microclaw
    } catch {
      Write-Info "Auto-run failed. Try running: microclaw"
    }
  } else {
    Write-Info "Could not find 'microclaw' in PATH."
    Write-Info "Add this directory to PATH: $InstallDir"
    Write-Info "Then run: $targetPath"
  }

  if (-not (Get-Command agent-browser.cmd -ErrorAction SilentlyContinue) -and -not (Get-Command agent-browser -ErrorAction SilentlyContinue)) {
    Write-Info "Optional: install browser automation support with:"
    Write-Info "  npm install -g agent-browser"
    Write-Info "  agent-browser install"
  }
} finally {
  Remove-Item -Recurse -Force $tmpDir.FullName -ErrorAction SilentlyContinue
}
