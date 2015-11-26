echo off

cd /d "%~dp0"
start "" "crypto_hybrid.exe" "d" "%~f1" "decrypt.txt" "private_key"
exit /b
