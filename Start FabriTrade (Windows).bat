@echo off
REM Double-click this file to start FabriTrade on Windows.
cd /d "%~dp0"
echo Starting FabriTrade...
start "" "http://localhost:3000"
node server.js
pause
