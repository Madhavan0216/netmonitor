@echo off
:: ============================================================================
:: NetMonitor - One-Click Start Script
:: ============================================================================
:: Last Updated: 2026-01-24
:: ============================================================================

title NetMonitor - Starting...
color 0A

echo.
echo  ============================================================
echo   _   _      _   __  __             _ _             
echo  ^| \ ^| ^| ___^| ^|_^|  \/  ^| ___  _ __ ^(_^) ^|_ ___  _ __ 
echo  ^|  \^| ^|/ _ \ __^| ^|\/^| ^|/ _ \^| '_ \^| ^| __/ _ \^| '__^|
echo  ^| ^|\  ^|  __/ ^|_^| ^|  ^| ^| ^(_^) ^| ^| ^| ^| ^| ^|^|^(_^) ^| ^|   
echo  ^|_^| \_^|\___^|\__^|_^|  ^|_^|\___/^|_^| ^|_^|_^|\__\___/^|_^|   
echo.
echo   Network Safety Monitoring Tool
echo  ============================================================
echo.

cd /d "%~dp0"

:: Check if Python venv exists
if not exist ".venv\Scripts\python.exe" goto :novenv

:: Check if node_modules exists
if not exist "frontend\node_modules" goto :installnpm

:continue
:: Create logs directory
if not exist "scripts\logs" mkdir "scripts\logs"

:: Update error.txt with session start
echo ================================================================================ > error_session.tmp
echo                            LIVE ERROR STREAM >> error_session.tmp
echo ================================================================================ >> error_session.tmp
echo Logger Started: %date% %time% >> error_session.tmp
echo Status: ACTIVE >> error_session.tmp
echo Collection Sources: Backend Server, Frontend Dev Server, Terminal >> error_session.tmp
echo -------------------------------------------------------------------------------- >> error_session.tmp
echo. >> error_session.tmp

:: Preserve existing error.txt content
if exist "error.txt" type error.txt >> error_session.tmp
move /y error_session.tmp error.txt > nul 2>&1

echo [1/3] Starting Backend Server...
echo.

:: Verify Python can import app.main before starting
echo    Verifying backend configuration...
cd backend
"%~dp0.venv\Scripts\python.exe" -c "import app.main" 2>nul
if errorlevel 1 goto :backenderr
cd ..
echo    Configuration OK.

:: Start Backend in new window
start "NetMonitor Backend" cmd /k "cd /d %~dp0backend && %~dp0.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000"

:: Wait for backend to initialize
echo    Waiting for backend to start...
timeout /t 4 /nobreak > nul

echo [2/3] Starting Frontend Dev Server...
echo.

:: Start Frontend in new window
start "NetMonitor Frontend" cmd /k "cd /d %~dp0frontend && npm run dev"

:: Wait for frontend to initialize
timeout /t 4 /nobreak > nul

echo [3/3] Services Starting...

:: Save PIDs info
echo Backend and Frontend servers started > scripts\.running
echo Started: %date% %time% >> scripts\.running

echo.
echo  ============================================================
echo   NETMONITOR STARTED SUCCESSFULLY!
echo  ============================================================
echo.
echo   Backend API:    http://127.0.0.1:8000
echo   API Docs:       http://127.0.0.1:8000/docs
echo   Frontend:       http://localhost:5173
echo.
echo   Default Login:  admin / changeme123
echo.
echo   Error Log:      error.txt
echo.
echo   To stop all services, run: stop.bat
echo  ============================================================
echo.

:: Open browser after short delay
timeout /t 2 /nobreak > nul
start http://localhost:5173

echo Press any key to close this window...
pause > nul
goto :eof

:novenv
color 0C
echo [ERROR] Python virtual environment not found!
echo.
echo Please run these commands first:
echo   python -m venv .venv
echo   .venv\Scripts\pip install -r backend\requirements.txt
echo.
pause
exit /b 1

:installnpm
color 0E
echo [WARNING] Frontend dependencies not installed.
echo Installing now...
cd frontend
call npm install
if errorlevel 1 goto :npmerr
cd ..
color 0A
goto :continue

:npmerr
color 0C
echo [ERROR] npm install failed!
pause
exit /b 1

:backenderr
cd ..
color 0C
echo [ERROR] Backend configuration error! Running diagnostic...
cd backend
"%~dp0.venv\Scripts\python.exe" -c "import app.main"
cd ..
echo.
echo Please fix the errors above and try again.
pause
exit /b 1
