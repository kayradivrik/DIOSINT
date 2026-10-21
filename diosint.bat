@echo off
title DIOSINT - Cyber Intelligence Console
color 05
chcp 65001 >nul
cd /d "%~dp0"

echo Starting Diosint Console...
if exist "venv\Scripts\python.exe" (
    venv\Scripts\python.exe terminal_app.py
) else (
    python terminal_app.py
)

pause
