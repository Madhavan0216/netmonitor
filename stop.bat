@echo off
:: ============================================================================
:: NetMonitor - One-Click Stop Script
:: ============================================================================
:: Double-click this file to stop all project services
:: - Stops Backend server (Python/Uvicorn)
:: - Stops Frontend server (Node/Vite)
:: - Stops Error monitor
:: - Updates error.txt status
:: ============================================================================
:: Last Updated: 2026-01-24
:: ============================================================================

title NetMonitor - Stopping...
color 0E

echo.
echo  ============================================================
echo   STOPPING NETMONITOR SERVICES...
echo  ============================================================
echo.

cd /d "%~dp0"

echo [1/4] Stopping Backend Server (Python/Uvicorn)...

:: Kill Python processes related to uvicorn
taskkill /F /FI "WINDOWTITLE eq NetMonitor Backend*" > nul 2>&1
taskkill /F /IM python.exe /FI "WINDOWTITLE eq NetMonitor*" > nul 2>&1

:: Find and kill uvicorn processes
for /f "tokens=2" %%a in ('tasklist /FI "IMAGENAME eq python.exe" /FO LIST ^| findstr "PID"') do (
    wmic process where "ProcessId=%%a" get CommandLine 2>nul | findstr /i "uvicorn" > nul && taskkill /F /PID %%a > nul 2>&1
)

echo    Done.
echo.

echo [2/4] Stopping Frontend Server (Node/Vite)...

:: Kill Node processes related to vite
taskkill /F /FI "WINDOWTITLE eq NetMonitor Frontend*" > nul 2>&1

:: Find and kill vite/node processes on port 5173
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":5173" ^| findstr "LISTENING"') do (
    taskkill /F /PID %%a > nul 2>&1
)

:: Kill any remaining node processes from this project
for /f "tokens=2" %%a in ('tasklist /FI "IMAGENAME eq node.exe" /FO LIST ^| findstr "PID"') do (
    wmic process where "ProcessId=%%a" get CommandLine 2>nul | findstr /i "netmonitor\frontend" > nul && taskkill /F /PID %%a > nul 2>&1
)

echo    Done.
echo.

echo [3/4] Stopping Error Monitor...

:: Kill error monitor window
taskkill /F /FI "WINDOWTITLE eq NetMonitor Error Monitor*" > nul 2>&1

echo    Done.
echo.

echo [4/4] Updating error.txt status...

:: Update error.txt to show stopped status
if exist "error.txt" (
    powershell -Command "(Get-Content error.txt) -replace 'Status: ACTIVE', 'Status: STOPPED (%date% %time%)' | Set-Content error.txt"
)

:: Remove running marker
if exist "scripts\.running" del "scripts\.running"

echo    Done.
echo.

color 0A
echo  ============================================================
echo   ALL NETMONITOR SERVICES STOPPED
echo  ============================================================
echo.
echo   Backend Server:   Stopped
echo   Frontend Server:  Stopped
echo   Error Monitor:    Stopped
echo.
echo   To start again, run: start.bat
echo  ============================================================
echo.

:: Also cleanup any orphan processes on common ports
echo Cleaning up any orphan processes...

:: Port 8000 (Backend)
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8000" ^| findstr "LISTENING"') do (
    echo    Killing process on port 8000 (PID: %%a)
    taskkill /F /PID %%a > nul 2>&1
)

:: Port 5173 (Frontend primary)
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":5173" ^| findstr "LISTENING"') do (
    echo    Killing process on port 5173 (PID: %%a)
    taskkill /F /PID %%a > nul 2>&1
)

:: Port 5174 (Frontend fallback)
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":5174" ^| findstr "LISTENING"') do (
    echo    Killing process on port 5174 (PID: %%a)
    taskkill /F /PID %%a > nul 2>&1
)

echo.
echo Cleanup complete.
echo.

timeout /t 3