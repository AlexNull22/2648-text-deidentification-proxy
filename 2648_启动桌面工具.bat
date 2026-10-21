@echo off
chcp 65001 >nul
cd /d "%~dp0"
set "TASK2648_PYTHON=%USERPROFILE%\2648_运行环境\Scripts\python.exe"
if not exist "%TASK2648_PYTHON%" (
  echo 请先运行2648_安装依赖.bat。
  pause
  exit /b 1
)
"%TASK2648_PYTHON%" -B "2648_桌面工具.py"
if errorlevel 1 pause
