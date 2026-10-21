@echo off
chcp 65001 >nul
set "TASK_2648_URL=https://www.upwork.com/jobs/Python-Node-Developer_~022111129198868522745/"
set "TASK_2648_FIREFOX=%ProgramFiles%\Mozilla Firefox\firefox.exe"
if exist "%TASK_2648_FIREFOX%" goto 2648_open
set "TASK_2648_FIREFOX=%ProgramFiles(x86)%\Mozilla Firefox\firefox.exe"
if exist "%TASK_2648_FIREFOX%" goto 2648_open
set "TASK_2648_FIREFOX=%LocalAppData%\Mozilla Firefox\firefox.exe"
if exist "%TASK_2648_FIREFOX%" goto 2648_open
where firefox.exe >nul 2>&1
if not errorlevel 1 (
    start "" firefox.exe -new-tab "%TASK_2648_URL%"
    exit /b 0
)
echo 未找到 Firefox。请先安装 Firefox，或将 Firefox 程序所在目录加入 PATH。
echo 项目链接：%TASK_2648_URL%
pause
exit /b 1

:2648_open
start "" "%TASK_2648_FIREFOX%" -new-tab "%TASK_2648_URL%"
exit /b 0
