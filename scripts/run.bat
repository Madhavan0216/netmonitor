@echo off
:: ============================================================================
:: NetMonitor Quick Start Script
:: ============================================================================
:: Usage: run.bat [start|stop]
:: Last Updated: 2026-01-24
:: ============================================================================

set PROJECT_ROOT=%~dp0..
set SCRIPTS_DIR=%PROJECT_ROOT%\scripts

if "%1"=="stop" (
    echo Stopping NetMonitor services...
    powershell -ExecutionPolicy Bypass -File "%SCRIPTS_DIR%\start_project.ps1" -Stop
) else if "%1"=="status" (
    echo Checking NetMonitor status...
    if exist "%SCRIPTS_DIR%\.running" (
        echo NetMonitor is RUNNING
        type "%SCRIPTS_DIR%\.running"
    ) else (
        echo NetMonitor is STOPPED
    )
) else (
    echo Starting NetMonitor services...
    powershell -ExecutionPolicy Bypass -File "%SCRIPTS_DIR%\start_project.ps1"
)
