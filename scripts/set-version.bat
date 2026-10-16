@echo off
:: Set the app version in every file that holds it, then rebuild with build.bat.
::   scripts\set-version.bat 2.0.8     set the version
::   scripts\set-version.bat           print the current version
:: Does the same as scripts/set-version.sh; see docs/DEVELOPMENT.md, "Version number".
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0set-version.ps1" %*
exit /b %errorlevel%
