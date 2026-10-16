@echo off
setlocal DisableDelayedExpansion
pushd "%~dp0" || exit /b 1

if not exist ".\mabi-patcher.exe" (
    echo ERROR: mabi-patcher.exe is missing.
    goto failed
)
if not exist ".\data\" (
    echo ERROR: data folder is missing.
    goto failed
)

set "templatePointer=C:\Nexon\Library\Mabinogi\appdata\package"

:findTemplate
set "template="
for /f "usebackq delims=" %%T in (`powershell.exe -NoProfile -Command "$ErrorActionPreference='Stop'; $p=$env:templatePointer.Trim().Trim([char]34); if ($p -and (Test-Path -LiteralPath $p)) { $item=Get-Item -LiteralPath $p; if ($item.PSIsContainer) { Get-ChildItem -LiteralPath $p -File -Filter 'data_*.it' | Where-Object { $_.Name -cmatch '^data_[0-9]{5}\.it$' } | Sort-Object Name -Descending | Select-Object -First 1 -ExpandProperty FullName } elseif ($item.Extension -ieq '.it') { $item.FullName } }"`) do set "template=%%T"
if defined template goto templateReady

echo No template found.
echo Enter a package folder or an original .it file.
echo Leave blank to use manual salts.
set "templatePointer="
set /p "templatePointer=Template location: "
if not defined templatePointer goto manualSalts
goto findTemplate

:manualSalts
set "template="
echo Using manual header and entries salts.
goto prompt

:templateReady
echo Using template: "%template%"

:prompt
set "file="
set /p "file=Enter archive name: "
if not defined file goto prompt
set "file=%file:"=%"
if not defined file goto prompt
if /i "%file:~-3%"==".it" set "file=%file:~0,-3%"
if not defined file goto prompt

if exist ".\%file%.it" (
    echo Output already exists. Choose another name or move the existing archive.
    goto prompt
)

if defined template goto packTemplate

".\mabi-patcher.exe" -v pack -i ".\data" --wrap-data -o ".\%file%.it" -k "1&w2!&w{Q)Fkz4e&p0" --entries-key "})wWb4?-sVGHNoPKpc" --encrypt-files
goto checkResult

:packTemplate
".\mabi-patcher.exe" -v pack -i ".\data" --wrap-data -o ".\%file%.it" --template "%template%"

:checkResult
if errorlevel 1 (
    echo Packing failed. See the error above or log.txt in this folder.
    goto failed
)

echo Packing completed.
pause
popd
exit /b 0

:failed
pause
popd
exit /b 1
