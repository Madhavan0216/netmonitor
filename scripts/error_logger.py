"""
NetMonitor Error Logger
=======================
Automated error collection from all project sources.
Runs as a background process and updates error.txt in real-time.

Usage:
    python scripts/error_logger.py start   # Start logging
    python scripts/error_logger.py stop    # Stop logging
    python scripts/error_logger.py status  # Check status
"""

import os
import sys
import re
import json
import time
import signal
import atexit
import threading
import subprocess
from datetime import datetime
from pathlib import Path
from queue import Queue
from typing import Optional

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent
ERROR_LOG_FILE = PROJECT_ROOT / "error.txt"
PID_FILE = PROJECT_ROOT / "scripts" / ".error_logger.pid"
LOG_QUEUE_FILE = PROJECT_ROOT / "scripts" / ".error_queue.json"

# Error patterns to detect
ERROR_PATTERNS = {
    "python_traceback": re.compile(r'Traceback \(most recent call last\):|^\s+File ".*", line \d+|^\w+Error:|^\w+Exception:', re.MULTILINE),
    "typescript_error": re.compile(r'error TS\d+:|TypeError:|SyntaxError:|ReferenceError:', re.IGNORECASE),
    "npm_error": re.compile(r'npm ERR!|npm WARN|ENOENT|EACCES|MODULE_NOT_FOUND', re.IGNORECASE),
    "vite_error": re.compile(r'\[vite\].*error|Failed to resolve|Build failed', re.IGNORECASE),
    "fastapi_error": re.compile(r'ERROR:|CRITICAL:|Internal Server Error|422 Unprocessable Entity|401 Unauthorized|403 Forbidden|404 Not Found|500 Internal Server Error', re.IGNORECASE),
    "uvicorn_error": re.compile(r'ERROR:.*uvicorn|Application startup failed', re.IGNORECASE),
    "database_error": re.compile(r'sqlite3\..*Error|sqlalchemy\..*Error|IntegrityError|OperationalError', re.IGNORECASE),
    "network_error": re.compile(r'ConnectionRefusedError|ConnectionResetError|TimeoutError|ECONNREFUSED', re.IGNORECASE),
    "import_error": re.compile(r'ModuleNotFoundError|ImportError|No module named', re.IGNORECASE),
    "permission_error": re.compile(r'PermissionError|Access is denied|EPERM', re.IGNORECASE),
    "generic_error": re.compile(r'error:|failed:|exception:|fatal:', re.IGNORECASE),
}

# Severity classification
SEVERITY_KEYWORDS = {
    "CRITICAL": ["CRITICAL", "FATAL", "crash", "Application startup failed", "Internal Server Error"],
    "ERROR": ["ERROR", "Error", "Exception", "failed", "ENOENT", "refused"],
    "WARNING": ["WARNING", "WARN", "deprecated", "422", "401", "403", "404"],
}


class ErrorLogger:
    """Main error logging class that monitors and records errors."""
    
    def __init__(self):
        self.running = False
        self.errors: list = []
        self.error_queue = Queue()
        self.start_time: Optional[datetime] = None
        self.log_lock = threading.Lock()
        
    def classify_severity(self, message: str) -> str:
        """Classify error severity based on keywords."""
        message_upper = message.upper()
        for severity, keywords in SEVERITY_KEYWORDS.items():
            for keyword in keywords:
                if keyword.upper() in message_upper:
                    return severity
        return "INFO"
    
    def detect_error_type(self, message: str) -> str:
        """Detect the type of error from the message."""
        for error_type, pattern in ERROR_PATTERNS.items():
            if pattern.search(message):
                return error_type.replace("_", " ").title()
        return "General Error"
    
    def format_error_entry(self, source: str, message: str, timestamp: datetime = None) -> dict:
        """Format an error entry for logging."""
        if timestamp is None:
            timestamp = datetime.now()
        
        return {
            "timestamp": timestamp.isoformat(),
            "source": source,
            "severity": self.classify_severity(message),
            "type": self.detect_error_type(message),
            "message": message.strip()[:500],  # Limit message length
        }
    
    def add_error(self, source: str, message: str):
        """Add an error to the queue."""
        if not message.strip():
            return
            
        # Check if this looks like an error
        is_error = any(pattern.search(message) for pattern in ERROR_PATTERNS.values())
        if not is_error:
            return
            
        entry = self.format_error_entry(source, message)
        self.error_queue.put(entry)
    
    def write_error_log(self):
        """Write accumulated errors to error.txt."""
        with self.log_lock:
            # Read existing content
            existing_content = ""
            if ERROR_LOG_FILE.exists():
                existing_content = ERROR_LOG_FILE.read_text(encoding='utf-8')
            
            # Find the LIVE ERRORS section or create it
            live_section_start = "=" * 80 + "\n                           LIVE ERROR STREAM\n" + "=" * 80
            live_section_marker = "LIVE ERROR STREAM"
            
            # Collect new errors from queue
            new_errors = []
            while not self.error_queue.empty():
                new_errors.append(self.error_queue.get())
            
            if not new_errors:
                return
            
            # Format new errors
            new_entries = []
            for error in new_errors:
                entry = f"""
[{error['timestamp']}]
Source: {error['source']}
Severity: {error['severity']}
Type: {error['type']}
Message: {error['message']}
{'-' * 40}"""
                new_entries.append(entry)
            
            # Update the file
            if live_section_marker in existing_content:
                # Append to existing live section
                parts = existing_content.split(live_section_marker)
                if len(parts) >= 2:
                    # Insert after the live section header
                    header_end = parts[1].find("\n" + "=" * 80)
                    if header_end == -1:
                        header_end = parts[1].find("\n\n")
                    
                    insert_point = existing_content.find(live_section_marker) + len(live_section_marker)
                    insert_point = existing_content.find("\n", insert_point) + 1
                    insert_point = existing_content.find("\n", insert_point) + 1
                    
                    new_content = (
                        existing_content[:insert_point] +
                        "\n".join(new_entries) + "\n" +
                        existing_content[insert_point:]
                    )
                    ERROR_LOG_FILE.write_text(new_content, encoding='utf-8')
            else:
                # Add live section at the top
                live_header = f"""{live_section_start}
Logger Started: {self.start_time.isoformat() if self.start_time else datetime.now().isoformat()}
Status: ACTIVE
Collection Sources: Terminal, Backend Server, Frontend Dev Server
{'-' * 80}
{"".join(new_entries)}

{existing_content}"""
                ERROR_LOG_FILE.write_text(live_header, encoding='utf-8')
    
    def monitor_process(self, process: subprocess.Popen, source: str):
        """Monitor a subprocess for errors."""
        def read_output(stream, stream_name):
            for line in iter(stream.readline, ''):
                if not self.running:
                    break
                if line:
                    self.add_error(f"{source} ({stream_name})", line)
        
        if process.stdout:
            stdout_thread = threading.Thread(
                target=read_output, 
                args=(process.stdout, "stdout"),
                daemon=True
            )
            stdout_thread.start()
        
        if process.stderr:
            stderr_thread = threading.Thread(
                target=read_output, 
                args=(process.stderr, "stderr"),
                daemon=True
            )
            stderr_thread.start()
    
    def log_writer_loop(self):
        """Background loop to periodically write errors to file."""
        while self.running:
            time.sleep(2)  # Write every 2 seconds
            self.write_error_log()
    
    def start(self):
        """Start the error logger."""
        self.running = True
        self.start_time = datetime.now()
        
        # Save PID
        PID_FILE.parent.mkdir(parents=True, exist_ok=True)
        PID_FILE.write_text(str(os.getpid()))
        
        # Start log writer thread
        writer_thread = threading.Thread(target=self.log_writer_loop, daemon=True)
        writer_thread.start()
        
        print(f"[ErrorLogger] Started at {self.start_time}")
        print(f"[ErrorLogger] Logging to: {ERROR_LOG_FILE}")
        print(f"[ErrorLogger] PID: {os.getpid()}")
        
        # Update error.txt with session start
        self.update_session_status("STARTED")
        
        return writer_thread
    
    def stop(self):
        """Stop the error logger."""
        self.running = False
        
        # Final write
        self.write_error_log()
        
        # Update status
        self.update_session_status("STOPPED")
        
        # Clean up PID file
        if PID_FILE.exists():
            PID_FILE.unlink()
        
        print(f"[ErrorLogger] Stopped at {datetime.now()}")
    
    def update_session_status(self, status: str):
        """Update the session status in error.txt."""
        if not ERROR_LOG_FILE.exists():
            return
            
        content = ERROR_LOG_FILE.read_text(encoding='utf-8')
        
        # Update status line
        if "Status: ACTIVE" in content and status == "STOPPED":
            content = content.replace(
                "Status: ACTIVE", 
                f"Status: STOPPED (Ended: {datetime.now().isoformat()})"
            )
            ERROR_LOG_FILE.write_text(content, encoding='utf-8')


# Global logger instance
logger = ErrorLogger()


def signal_handler(signum, frame):
    """Handle shutdown signals."""
    print("\n[ErrorLogger] Received shutdown signal...")
    logger.stop()
    sys.exit(0)


def start_logging():
    """Start the error logging service."""
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    atexit.register(logger.stop)
    
    # Start logger
    writer_thread = logger.start()
    
    # Keep main thread alive
    try:
        while logger.running:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.stop()


def stop_logging():
    """Stop the error logging service."""
    if PID_FILE.exists():
        pid = int(PID_FILE.read_text())
        try:
            os.kill(pid, signal.SIGTERM)
            print(f"[ErrorLogger] Sent stop signal to PID {pid}")
        except ProcessLookupError:
            print(f"[ErrorLogger] Process {pid} not found")
            PID_FILE.unlink()
    else:
        print("[ErrorLogger] No active logger found")


def check_status():
    """Check the status of the error logger."""
    if PID_FILE.exists():
        pid = int(PID_FILE.read_text())
        try:
            os.kill(pid, 0)  # Check if process exists
            print(f"[ErrorLogger] Running (PID: {pid})")
            return True
        except ProcessLookupError:
            print("[ErrorLogger] Not running (stale PID file)")
            PID_FILE.unlink()
            return False
    else:
        print("[ErrorLogger] Not running")
        return False


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python error_logger.py [start|stop|status]")
        sys.exit(1)
    
    command = sys.argv[1].lower()
    
    if command == "start":
        if check_status():
            print("[ErrorLogger] Already running")
        else:
            start_logging()
    elif command == "stop":
        stop_logging()
    elif command == "status":
        check_status()
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
