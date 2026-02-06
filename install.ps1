# Cyberstrike CLI Installer for Windows
# Usage: irm https://cyberstrike.io/install.ps1 | iex

$ErrorActionPreference = "Stop"

$Repo = "CyberStrikeus/cyberstrike.io"
$InstallDir = if ($env:CYBERSTRIKE_INSTALL_DIR) { $env:CYBERSTRIKE_INSTALL_DIR } else { "$env:LOCALAPPDATA\cyberstrike" }

function Write-Info { param($Message) Write-Host "[INFO] $Message" -ForegroundColor Green }
function Write-Warn { param($Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-Err { param($Message) Write-Host "[ERROR] $Message" -ForegroundColor Red; exit 1 }

function Get-Architecture {
    if ([Environment]::Is64BitOperatingSystem) {
        if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") {
            return "arm64"
        }
        return "x64"
    }
    Write-Err "32-bit systems are not supported"
}

function Get-LatestVersion {
    try {
        $response = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -UseBasicParsing
        return $response.tag_name
    } catch {
        return $null
    }
}

function Install-Cyberstrike {
    Write-Info "Installing Cyberstrike CLI..."

    $Arch = Get-Architecture
    $Version = Get-LatestVersion

    if (-not $Version) {
        $Version = "v1.0.1"
        Write-Warn "Could not fetch latest version, using $Version"
    }

    Write-Info "Detected: windows-$Arch"
    Write-Info "Version: $Version"

    # Construct download URL
    $AssetName = "cyberstrike-windows-$Arch.zip"
    $DownloadUrl = "https://github.com/$Repo/releases/download/$Version/$AssetName"

    # Create install directory
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    # Download
    Write-Info "Downloading from $DownloadUrl..."
    $TempDir = Join-Path $env:TEMP "cyberstrike-install"
    $TempFile = Join-Path $TempDir $AssetName

    if (Test-Path $TempDir) {
        Remove-Item -Recurse -Force $TempDir
    }
    New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

    try {
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempFile -UseBasicParsing
    } catch {
        Write-Err "Failed to download: $_"
    }

    # Extract
    Write-Info "Extracting..."
    Expand-Archive -Path $TempFile -DestinationPath $TempDir -Force

    # Find and move binary
    $Binary = Get-ChildItem -Path $TempDir -Recurse -Filter "cyberstrike.exe" | Select-Object -First 1
    if (-not $Binary) {
        # Try without .exe extension
        $Binary = Get-ChildItem -Path $TempDir -Recurse -Filter "cyberstrike" | Select-Object -First 1
    }

    if (-not $Binary) {
        Write-Err "Could not find cyberstrike binary in archive"
    }

    $DestPath = Join-Path $InstallDir "cyberstrike.exe"
    Copy-Item -Path $Binary.FullName -Destination $DestPath -Force

    # Cleanup
    Remove-Item -Recurse -Force $TempDir

    Write-Info "Installed to $DestPath"

    # Check if install dir is in PATH
    $UserPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($UserPath -notlike "*$InstallDir*") {
        Write-Warn "$InstallDir is not in your PATH"
        Write-Host ""
        Write-Host "Add it to your PATH by running:" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  `$env:PATH = `"$InstallDir;`$env:PATH`""
        Write-Host ""
        Write-Host "Or permanently add it:" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  [Environment]::SetEnvironmentVariable('PATH', `"$InstallDir;`$env:PATH`", 'User')"
        Write-Host ""

        # Offer to add to PATH
        $addToPath = Read-Host "Would you like to add it to your PATH now? (Y/n)"
        if ($addToPath -eq "" -or $addToPath -eq "Y" -or $addToPath -eq "y") {
            [Environment]::SetEnvironmentVariable("PATH", "$InstallDir;$UserPath", "User")
            $env:PATH = "$InstallDir;$env:PATH"
            Write-Info "Added to PATH. You may need to restart your terminal."
        }
    }

    Write-Host ""
    Write-Info "Cyberstrike CLI installed successfully!"
    Write-Host ""
    Write-Host "  Run 'cyberstrike --help' to get started" -ForegroundColor Cyan
    Write-Host ""
}

Install-Cyberstrike
