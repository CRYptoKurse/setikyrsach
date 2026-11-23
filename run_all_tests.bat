@echo off
cd /d "%~dp0"
where py >nul 2>1
if not errorlevel 1 (
    py -3 -m run_all_tests
    exit /b %ERRORLEVEL%
)
where python >nul 2>1
if not errorlevel 1 (
    python -m run_all_tests
    exit /b %ERRORLEVEL%
)
echo Python 3.11+ was not found in PATH.
echo Install Python or run the script via VS Code with the project interpreter selected.
exit /b 1
