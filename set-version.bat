@echo off
:: Set the app version in every file that holds it, then rebuild with build.bat.
::   set-version.bat 2.0.6     set the version
::   set-version.bat           print the current version
:: Does the same as scripts/set-version.sh; see docs/DEVELOPMENT.md, "Version number".
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\set-version.ps1" %*
exit /b %errorlevel%
