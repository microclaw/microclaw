# Install MicroClaw Code (mccode) from the latest GitHub release.
#
#   iwr https://microclaw.org/install-mccode.ps1 -UseBasicParsing | iex
#
# The archive is verified against the release's SHA256SUMS.txt before the
# binary is installed.
param(
  [string]$Repo = $(if ($env:MCCODE_REPO) { $env:MCCODE_REPO } else { 'microclaw/microclaw' }),
  [string]$InstallDir = $(if ($env:MCCODE_INSTALL_DIR) { $env:MCCODE_INSTALL_DIR } else { Join-Path $env:USERPROFILE '.local\bin' }),
  [string]$Version = $(if ($env:MCCODE_VERSION) { $env:MCCODE_VERSION } else { '' })
)

$ErrorActionPreference = 'Stop'
$BinName = 'mccode.exe'

function Write-Info([string]$msg) { Write-Host $msg }

function Path-Contains([string]$pathValue, [string]$dir) {
  if ([string]::IsNullOrWhiteSpace($pathValue)) { return $false }
  $needle = $dir.Trim().TrimEnd('\').ToLowerInvariant()
  foreach ($part in $pathValue.Split(';')) {
    if ([string]::IsNullOrWhiteSpace($part)) { continue }
    if ($part.Trim().TrimEnd('\').ToLowerInvariant() -eq $needle) { return $true }
  }
  return $false
}

$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
if ("$arch" -ne 'X64') {
  throw "No prebuilt mccode for Windows $arch. Build it from source: cargo install --git https://github.com/$Repo microclaw-code"
}

if ([string]::IsNullOrWhiteSpace($Version)) {
  $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ 'User-Agent' = 'mccode-installer' }
  $tag = $release.tag_name
} else {
  $tag = 'v' + $Version.TrimStart('v')
}
$ver = $tag.TrimStart('v')
$asset = "mccode-$ver-x86_64-windows-msvc.zip"
$base = "https://github.com/$Repo/releases/download/$tag"

Write-Info "Installing mccode $ver for Windows x86_64..."
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("mccode-install-" + [guid]::NewGuid())
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
try {
  $sumsPath = Join-Path $tmp 'SHA256SUMS.txt'
  Invoke-WebRequest -Uri "$base/SHA256SUMS.txt" -OutFile $sumsPath -UseBasicParsing
  $expected = $null
  foreach ($line in Get-Content $sumsPath) {
    $parts = $line -split '\s+'
    if ($parts.Count -ge 2 -and $parts[1].TrimStart('*') -eq $asset) { $expected = $parts[0].ToLowerInvariant() }
  }
  if (-not $expected) {
    throw "Release $tag has no $asset. Build it from source: cargo install --git https://github.com/$Repo microclaw-code"
  }

  $archive = Join-Path $tmp $asset
  Write-Info "Downloading $base/$asset"
  Invoke-WebRequest -Uri "$base/$asset" -OutFile $archive -UseBasicParsing
  $actual = (Get-FileHash -Algorithm SHA256 -Path $archive).Hash.ToLowerInvariant()
  if ($actual -ne $expected) {
    throw "Checksum mismatch for $asset (expected $expected, got $actual); not installing."
  }
  Write-Info 'Checksum verified.'

  Expand-Archive -Path $archive -DestinationPath $tmp -Force
  $bin = Get-ChildItem -Path $tmp -Recurse -Filter $BinName | Select-Object -First 1
  if ($null -eq $bin) { throw "$asset does not contain $BinName" }

  New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
  $target = Join-Path $InstallDir $BinName
  $staged = Join-Path $InstallDir ".$BinName.tmp.$PID"
  Copy-Item -Path $bin.FullName -Destination $staged -Force
  Move-Item -Path $staged -Destination $target -Force

  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (-not (Path-Contains $userPath $InstallDir)) {
    $newPath = if ([string]::IsNullOrWhiteSpace($userPath)) { $InstallDir } else { "$userPath;$InstallDir" }
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    Write-Info "Added '$InstallDir' to your user PATH (open a new terminal to use it)."
  }
  if (-not (Path-Contains $env:Path $InstallDir)) { $env:Path = "$env:Path;$InstallDir" }

  Write-Info ''
  Write-Info "Installed mccode $ver to $target."
  Write-Info 'Next steps:'
  Write-Info '  mccode setup        # choose a model provider and key'
  Write-Info '  cd your\repo; mccode'
  Write-Info 'Update later with: mccode update'
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
