@echo off
start /B /MIN node server.js
echo LensFlow запущен на http://localhost:3000
timeout /t 3 >nul
start http://localhost:3000
