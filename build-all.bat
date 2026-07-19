@echo off
echo ========================================
echo mabi-pack2: STARTING BUILD
echo ========================================

echo [1/6] DEEP CLEAN: Killing all caches...
taskkill /F /IM mabi-pack2.exe /T >nul 2>&1
timeout /t 2 /nobreak >nul
if exist "mabi-pack2.exe" del /f /q "mabi-pack2.exe"
if exist "mabi-pack2-setup.exe" del /f /q "mabi-pack2-setup.exe"
if exist "mabi-pack2-setup.msi" del /f /q "mabi-pack2-setup.msi"
if exist "gui\dist" rd /s /q "gui\dist"
if exist "gui\src-tauri\target" rd /s /q "gui\src-tauri\target"

echo [2/6] Dependencies: refreshing Node modules...
cd gui
call npm install
if %errorlevel% neq 0 (
    echo Error: npm install failed.
    pause
    exit /b %errorlevel%
)

echo [3/6] Build: compiling mabi-pack2 core...
call npm run tauri build
if %errorlevel% neq 0 (
    echo Error: Tauri build failed.
    pause
    exit /b %errorlevel%
)

echo [4/6] Export: Moving binaries to root...
cd ..

:: Use xcopy for robust delivery as requested
xcopy /Y /S "gui\src-tauri\target\release\mabi-pack2*" "."
if exist "mabi-pack2.d" del /f /q "mabi-pack2.d"

echo [5/6] Verification: Checking file existence...
if not exist "mabi-pack2.exe" (
    echo FATAL ERROR: Binary missing after build.
    pause
    exit /b 1
)

echo [6/6] Space: Cleaning up...
rd /s /q "gui\node_modules"

echo.
echo ========================================
echo BUILD SUCCESSFUL!
echo Binary: mabi-pack2.exe
echo NSIS Setup: mabi-pack2-setup.exe (Multi-lingual)
echo MSI Setup: mabi-pack2-setup.msi (en-US only)
echo ========================================
pause
