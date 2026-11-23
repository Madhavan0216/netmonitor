<#
.SYNOPSIS
    NetMonitor Project Startup Script with Error Logging
.DESCRIPTION
    Starts the error logger, backend server, and frontend dev server.
    All output is captured and logged to error.txt automatically.
.USAGE
    .\scripts\start_project.ps1         # Start everything
    .\scripts\start_project.ps1 -Stop   # Stop everything
.NOTES
    Last Updated: 2026-01-24
#>

param(
    [switch]$Stop,
    [switch]$BackendOnly,
    [switch]$FrontendOnly
)

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$ErrorLogFile = Join-Path $ProjectRoot "error.txt"
$BackendDir = Join-Path $ProjectRoot "backend"
$FrontendDir = Join-Path $ProjectRoot "frontend"
$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$ScriptsDir = Join-Path $ProjectRoot "scripts"
$PidFile = Join-Path $ScriptsDir ".pids.json"
$LogDir = Join-Path $ScriptsDir "logs"

# Ensure log directory exists
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

# Log files for each service
$BackendLog = Join-Path $LogDir "backend.log"
$FrontendLog = Join-Path $LogDir "frontend.log"
$ErrorCollectorLog = Join-Path $LogDir "error_collector.log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp] [$Level] $Message"
    Write-Host $entry
    Add-Content -Path $ErrorCollectorLog -Value $entry
}

function Update-ErrorTxt {
    param([string]$Source, [string]$Message, [string]$Severity = "ERROR")
    
    $timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
    $entry = @"

[$timestamp]
Source: $Source
Severity: $Severity
Message: $Message
----------------------------------------
"@
    
    # Read existing content
    $content = ""
    if (Test-Path $ErrorLogFile) {
        $content = Get-Content $ErrorLogFile -Raw -ErrorAction SilentlyContinue
    }
    
    # Check if LIVE ERROR STREAM section exists
    if ($content -match "LIVE ERROR STREAM") {
        # Find insertion point after the header
        $lines = $content -split "`n"
        $insertIndex = 0
        $foundHeader = $false
        
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match "LIVE ERROR STREAM") {
                $foundHeader = $true
            }
            if ($foundHeader -and $lines[$i] -match "^-{40,}$") {
                $insertIndex = $i + 1
                break
            }
        }
        
        if ($insertIndex -gt 0) {
            $newLines = @($lines[0..($insertIndex-1)]) + @($entry) + @($lines[$insertIndex..($lines.Count-1)])
            $newContent = $newLines -join "`n"
            Set-Content -Path $ErrorLogFile -Value $newContent -NoNewline
        }
    }
}

function Watch-LogFile {
    param(
        [string]$LogFile,
        [string]$Source,
        [scriptblock]$ErrorPatterns
    )
    
    # Error patterns to detect
    $patterns = @(
        'error',
        'Error',
        'ERROR',
        'Exception',
        'EXCEPTION',
        'Traceback',
        'failed',
        'FAILED',
        'FATAL',
        'CRITICAL',
        'ModuleNotFoundError',
        'ImportError',
        'TypeError',
        'SyntaxError',
        'npm ERR',
        'ENOENT',
        '500 Internal',
        '401 Unauthorized',
        '403 Forbidden',
        '404 Not Found',
        '422 Unprocessable'
    )
    
    $lastPosition = 0
    
    while ($true) {
        Start-Sleep -Milliseconds 500
        
        if (Test-Path $LogFile) {
            $content = Get-Content $LogFile -Raw -ErrorAction SilentlyContinue
            if ($content -and $content.Length -gt $lastPosition) {
                $newContent = $content.Substring($lastPosition)
                $lastPosition = $content.Length
                
                # Check for errors in new content
                foreach ($pattern in $patterns) {
                    if ($newContent -match $pattern) {
                        # Extract relevant lines
                        $lines = $newContent -split "`n" | Where-Object { $_ -match $pattern }
                        foreach ($line in $lines) {
                            if ($line.Trim()) {
                                $severity = "ERROR"
                                if ($line -match "CRITICAL|FATAL") { $severity = "CRITICAL" }
                                elseif ($line -match "WARNING|WARN") { $severity = "WARNING" }
                                
                                Update-ErrorTxt -Source $Source -Message $line.Trim() -Severity $severity
                            }
                        }
                        break
                    }
                }
            }
        }
    }
}

function Start-Services {
    Write-Log "Starting NetMonitor services..."
    
    # Initialize error.txt with live header
    $liveHeader = @"
================================================================================
                           LIVE ERROR STREAM
================================================================================
Logger Started: $(Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
Status: ACTIVE
Collection Sources: Backend Server (Uvicorn), Frontend Dev Server (Vite), Terminal
--------------------------------------------------------------------------------

"@
    
    # Preserve existing content and add live header
    $existingContent = ""
    if (Test-Path $ErrorLogFile) {
        $existingContent = Get-Content $ErrorLogFile -Raw -ErrorAction SilentlyContinue
        # Remove old live header if exists
        if ($existingContent -match "LIVE ERROR STREAM") {
            $existingContent = $existingContent -replace "(?s)={80}\s+LIVE ERROR STREAM.*?-{80}\s*\n", ""
        }
    }
    
    Set-Content -Path $ErrorLogFile -Value ($liveHeader + $existingContent) -NoNewline
    
    # Store PIDs
    $pids = @{}
    
    # Add Nmap to PATH
    $env:PATH += ";C:\Program Files (x86)\Nmap"
    
    # Start Backend
    if (-not $FrontendOnly) {
        Write-Log "Starting backend server..."
        
        # Clear old log
        if (Test-Path $BackendLog) { Remove-Item $BackendLog -Force }
        
        $backendProcess = Start-Process -FilePath $VenvPython `
            -ArgumentList "-m", "uvicorn", "app.main:app", "--reload", "--host", "127.0.0.1", "--port", "8000" `
            -WorkingDirectory $BackendDir `
            -RedirectStandardOutput $BackendLog `
            -RedirectStandardError $BackendLog `
            -PassThru `
            -WindowStyle Hidden
        
        $pids["backend"] = $backendProcess.Id
        Write-Log "Backend started (PID: $($backendProcess.Id))"
        
        # Start backend log watcher in background
        $backendWatcher = Start-Job -ScriptBlock {
            param($LogFile, $ErrorLogFile)
            
            $patterns = @('error', 'Error', 'ERROR', 'Exception', 'Traceback', 'failed', 'CRITICAL', 'ModuleNotFoundError')
            $lastPosition = 0
            
            while ($true) {
                Start-Sleep -Milliseconds 1000
                if (Test-Path $LogFile) {
                    try {
                        $content = [System.IO.File]::ReadAllText($LogFile)
                        if ($content.Length -gt $lastPosition) {
                            $newContent = $content.Substring($lastPosition)
                            $lastPosition = $content.Length
                            
                            foreach ($pattern in $patterns) {
                                if ($newContent -match $pattern) {
                                    $lines = $newContent -split "`n" | Where-Object { $_ -match $pattern -and $_.Trim() }
                                    foreach ($line in $lines) {
                                        $timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
                                        $entry = "`n[$timestamp]`nSource: Backend Server (Uvicorn)`nSeverity: ERROR`nMessage: $($line.Trim())`n" + ("-" * 40) + "`n"
                                        
                                        [System.IO.File]::AppendAllText($ErrorLogFile, $entry)
                                    }
                                    break
                                }
                            }
                        }
                    } catch {}
                }
            }
        } -ArgumentList $BackendLog, $ErrorLogFile
        
        $pids["backendWatcher"] = $backendWatcher.Id
    }
    
    # Start Frontend
    if (-not $BackendOnly) {
        Write-Log "Starting frontend dev server..."
        Start-Sleep -Seconds 2  # Wait for backend to be ready
        
        # Clear old log
        if (Test-Path $FrontendLog) { Remove-Item $FrontendLog -Force }
        
        $frontendProcess = Start-Process -FilePath "npm" `
            -ArgumentList "run", "dev" `
            -WorkingDirectory $FrontendDir `
            -RedirectStandardOutput $FrontendLog `
            -RedirectStandardError $FrontendLog `
            -PassThru `
            -WindowStyle Hidden
        
        $pids["frontend"] = $frontendProcess.Id
        Write-Log "Frontend started (PID: $($frontendProcess.Id))"
        
        # Start frontend log watcher in background
        $frontendWatcher = Start-Job -ScriptBlock {
            param($LogFile, $ErrorLogFile)
            
            $patterns = @('error', 'Error', 'ERROR', 'TypeError', 'SyntaxError', 'npm ERR', 'ENOENT', 'failed')
            $lastPosition = 0
            
            while ($true) {
                Start-Sleep -Milliseconds 1000
                if (Test-Path $LogFile) {
                    try {
                        $content = [System.IO.File]::ReadAllText($LogFile)
                        if ($content.Length -gt $lastPosition) {
                            $newContent = $content.Substring($lastPosition)
                            $lastPosition = $content.Length
                            
                            foreach ($pattern in $patterns) {
                                if ($newContent -match $pattern) {
                                    $lines = $newContent -split "`n" | Where-Object { $_ -match $pattern -and $_.Trim() }
                                    foreach ($line in $lines) {
                                        $timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
                                        $entry = "`n[$timestamp]`nSource: Frontend Dev Server (Vite)`nSeverity: ERROR`nMessage: $($line.Trim())`n" + ("-" * 40) + "`n"
                                        
                                        [System.IO.File]::AppendAllText($ErrorLogFile, $entry)
                                    }
                                    break
                                }
                            }
                        }
                    } catch {}
                }
            }
        } -ArgumentList $FrontendLog, $ErrorLogFile
        
        $pids["frontendWatcher"] = $frontendWatcher.Id
    }
    
    # Save PIDs to file
    $pids | ConvertTo-Json | Set-Content $PidFile
    
    Write-Log "All services started successfully!"
    Write-Log "Backend: http://127.0.0.1:8000"
    Write-Log "Frontend: http://localhost:5173"
    Write-Log "Error log: $ErrorLogFile"
    Write-Log ""
    Write-Log "Use '.\scripts\start_project.ps1 -Stop' to stop all services"
}

function Stop-Services {
    Write-Log "Stopping NetMonitor services..."
    
    if (Test-Path $PidFile) {
        $pids = Get-Content $PidFile | ConvertFrom-Json
        
        # Stop processes
        foreach ($name in @("frontend", "backend")) {
            if ($pids.$name) {
                try {
                    $proc = Get-Process -Id $pids.$name -ErrorAction SilentlyContinue
                    if ($proc) {
                        Stop-Process -Id $pids.$name -Force -ErrorAction SilentlyContinue
                        Write-Log "Stopped $name (PID: $($pids.$name))"
                    }
                } catch {
                    Write-Log "Process $name already stopped" "WARNING"
                }
            }
        }
        
        # Stop watcher jobs
        Get-Job | Stop-Job -PassThru | Remove-Job -Force
        
        Remove-Item $PidFile -Force
    }
    
    # Also kill any remaining node/python processes for this project
    Get-Process -Name "node" -ErrorAction SilentlyContinue | Where-Object {
        $_.Path -like "*netmonitor*"
    } | Stop-Process -Force -ErrorAction SilentlyContinue
    
    # Update error.txt status
    if (Test-Path $ErrorLogFile) {
        $content = Get-Content $ErrorLogFile -Raw
        $content = $content -replace "Status: ACTIVE", "Status: STOPPED (Ended: $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss'))"
        Set-Content -Path $ErrorLogFile -Value $content -NoNewline
    }
    
    Write-Log "All services stopped."
}

# Main execution
if ($Stop) {
    Stop-Services
} else {
    Start-Services
}
