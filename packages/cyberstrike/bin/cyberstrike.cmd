@echo off
setlocal

:: Get the directory where this script is located
set "SCRIPT_DIR=%~dp0"
set "BINARY=%SCRIPT_DIR%cyberstrike-bin.exe"

:: Check if binary exists
if not exist "%BINARY%" (
    echo Error: Cyberstrike binary not found.
    echo.
    echo Run the postinstall script to download the binary:
    echo   npm run postinstall
    echo.
    echo Or reinstall the package:
    echo   npm install -g cyberstrike
    echo.
    echo Alternative installation methods:
    echo   - Homebrew: brew install CyberStrikeus/tap/cyberstrike
    echo   - curl: curl -fsSL https://cyberstrike.io/install.sh ^| bash
    exit /b 1
)

:: Execute the binary
"%BINARY%" %*
