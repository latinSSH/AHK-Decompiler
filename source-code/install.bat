@echo off
setlocal EnableDelayedExpansion

title AHK Decompiler Launcher

echo.
echo  Starting AHK Decompiler (Mango Edition)
echo  =======================================
echo.

set "PYTHON_CMD=python"
set "FOUND=0"

for %%p in (
    python
    py
    python3
    "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
    "%ProgramFiles%\Python312\python.exe"
    "%ProgramFiles%\Python311\python.exe"
    "%ProgramFiles(x86)%\Python312\python.exe"
    "%ProgramFiles(x86)%\Python311\python.exe"
) do (
    %%p --version >nul 2>&1
    if !ERRORLEVEL! EQU 0 (
        set "PYTHON_CMD=%%p"
        set FOUND=1
        goto :python_found
    )
)

:python_found
if %FOUND%==0 (
    echo ERROR: Python not found.
    echo.
    echo   Please install Python 3.9 or newer.
    echo   Recommended: https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

for /f "tokens=2 delims=." %%v in ('%PYTHON_CMD% -V 2^>^&1') do set "PY_MINOR=%%v"
if %PY_MINOR% LSS 9 (
    echo ERROR: Python 3.9 or newer is required ^(found %PYTHON_CMD% -V^)
    echo.
    pause
    exit /b 1
)

echo Using: %PYTHON_CMD%
%PYTHON_CMD% --version
echo.

set "VENV=.venv"

if not exist "%VENV%\Scripts\activate.bat" (
    echo Creating virtual environment...
    %PYTHON_CMD% -m venv %VENV%
    if errorlevel 1 (
        echo Failed to create virtual environment.
        pause
        exit /b 1
    )
)

echo Activating virtual environment...
call "%VENV%\Scripts\activate.bat"
if errorlevel 1 (
    echo Failed to activate virtual environment.
    pause
    exit /b 1
)

echo.
echo Updating pip...
python -m pip install --upgrade pip --quiet

echo.
echo Installing required packages...
pip install --upgrade ^
    customtkinter ^
    pefile

if errorlevel 1 (
    echo.
    echo Some packages failed to install.
    echo You can try running the command manually:
    echo     pip install customtkinter pefile
    echo.
    pause
    goto :launch
)

echo.
echo All dependencies installed/upgraded.
echo.

:launch

echo Starting AHK Decompiler...
echo.

python ahkdecompiler.py
pause