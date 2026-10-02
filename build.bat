@echo off
setlocal enabledelayedexpansion
echo ========================================
echo mabi-patcher: STARTING BUILD
echo ========================================

:: Dynamically get version from tauri.conf.json using PowerShell
for /f "usebackq tokens=*" %%v in (`powershell -NoProfile -Command "(Get-Content gui/src-tauri/tauri.conf.json | ConvertFrom-Json).version"`) do set VERSION=%%v

:: Turn on the repo pre-commit gate (scripts/precommit-check.sh) for local commits
git config core.hooksPath .githooks >nul 2>&1

echo [1/6] Cleaning up old build artifacts...
taskkill /F /IM mabi-patcher.exe /T >nul 2>&1
timeout /t 2 /nobreak >nul
if exist "mabi-patcher.exe" del /f /q "mabi-patcher.exe"
if exist "release\mabi-patcher-setup.exe" del /f /q "release\mabi-patcher-setup.exe"                                                                                                                                                                                
if exist "release\mabi-patcher-setup.msi" del /f /q "release\mabi-patcher-setup.msi"  
:: Only for full build
:: if exist "gui\dist" rd /s /q "gui\dist"
:: if exist "gui\src-tauri\target" rd /s /q "gui\src-tauri\target"

echo [2/6] Installing frontend dependencies...
cd gui
call npm install
if %errorlevel% neq 0 (
    echo Error: npm install failed.
    pause
    exit /b %errorlevel%
)

echo [3/6] Building mabi-patcher v%VERSION% (Turbo Shrink Release)...
call npm run tauri build
if %errorlevel% neq 0 (
    echo Error: Tauri build failed.
    pause
    exit /b %errorlevel%
)

echo [4/6] Moving binary and installers to root...
cd ..

xcopy /Y /S "gui\src-tauri\target\release\mabi-patcher*" "."                                                                                                                                                                                                      
if exist "mabi-patcher.d" del /f /q "mabi-patcher.d"

echo [5/6] Verification: Checking file existence...
if not exist "mabi-patcher.exe" (
    echo FATAL ERROR: Binary missing after build.
    exit /b 1
)

echo [6/6] Finalizing...
:: Only for full build
::rd /s /q "gui\node_modules"

echo.
echo ========================================
echo BUILD SUCCESSFUL!
echo Binary: mabi-patcher.exe
echo NSIS Setup: mabi-patcher-setup.exe (Multi-lingual)
echo MSI Setup: mabi-patcher-setup.msi (en-US only)
echo Version: %VERSION%
echo ========================================
