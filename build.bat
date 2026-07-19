@echo off
setlocal enabledelayedexpansion
echo ========================================
echo mabi-pack2: STARTING BUILD
echo ========================================

:: Dynamically get version from tauri.conf.json using PowerShell
for /f "usebackq tokens=*" %%v in (`powershell -NoProfile -Command "(Get-Content gui/src-tauri/tauri.conf.json | ConvertFrom-Json).version"`) do set VERSION=%%v

echo [1/6] Cleaning up old build artifacts...
taskkill /F /IM mabi-pack2.exe /T >nul 2>&1
timeout /t 2 /nobreak >nul
if exist "mabi-pack2.exe" del /f /q "mabi-pack2.exe"
if exist "release\mabi-pack2-setup.exe" del /f /q "release\mabi-pack2-setup.exe"                                                                                                                                                                                
if exist "release\mabi-pack2-setup.msi" del /f /q "release\mabi-pack2-setup.msi"  
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

echo [3/6] Building mabi-pack2 v%VERSION% (Turbo Shrink Release)...
call npm run tauri build
if %errorlevel% neq 0 (
    echo Error: Tauri build failed.
    pause
    exit /b %errorlevel%
)

echo [4/6] Moving binary and installers to root...
cd ..

xcopy /Y /S "gui\src-tauri\target\release\mabi-pack2*" "."                                                                                                                                                                                                      
if exist "mabi-pack2.d" del /f /q "mabi-pack2.d"

echo [5/6] Verification: Checking file existence...
if not exist "mabi-pack2.exe" (
    echo FATAL ERROR: Binary missing after build.
    exit /b 1
)

echo [6/6] Finalizing...
:: Only for full build
::rd /s /q "gui\node_modules"

echo.
echo ========================================
echo BUILD SUCCESSFUL!
echo Binary: mabi-pack2.exe
echo NSIS Setup: mabi-pack2-setup.exe (Multi-lingual)
echo MSI Setup: mabi-pack2-setup.msi (en-US only)
echo Version: %VERSION%
echo ========================================
