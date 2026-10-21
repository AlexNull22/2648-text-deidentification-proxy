@echo off
chcp 65001 >nul
set "TASK2648_ENV=%USERPROFILE%\2648_运行环境"
if not exist "%TASK2648_ENV%\Scripts\python.exe" python -B -m venv "%TASK2648_ENV%"
if errorlevel 1 exit /b 1
"%TASK2648_ENV%\Scripts\python.exe" -B -m pip install --disable-pip-version-check --quiet -r "%~dp02648_依赖.txt"
if errorlevel 1 exit /b 1
echo 2648_运行环境已准备好。
