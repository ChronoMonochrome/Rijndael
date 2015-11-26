echo off
cd /d "%~dp0"
start "" "crypto_hybrid.exe" "e" "%~f1" "encrypt.txt"
exit /b
