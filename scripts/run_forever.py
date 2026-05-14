#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cross-platform script to run scan with retry logic (max 5 retries).
Monitors for rate limit errors and restarts the process if needed.
"""

import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path


def check_rate_limit_error(log_file_path):
    """Check if log file contains rate limit error by searching the entire file."""
    if not os.path.exists(log_file_path):
        return False
    
    try:
        # Try to read the file (may fail on Windows if subprocess has it open)
        # On Unix systems, we can read files that are being written to
        with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            # Read the ENTIRE file to search for the error
            f.seek(0)
            content = f.read()
            
            # Case-insensitive check for the error message
            content_lower = content.lower()
            return "request too large for" in content_lower
    except (IOError, OSError, PermissionError):
        # File might be locked on Windows, or other I/O error
        # Return False and we'll check again later
        return False


def monitor_process(process, output_log, error_log):
    """Monitor process and check for rate limit errors."""
    while process.poll() is None:
        time.sleep(1)
        
        # Check output.log for rate limit error
        # Note: We need to read the file while it's being written to
        if check_rate_limit_error(output_log):
            print("Rate limit error detected in stdout - stopping process")
            try:
                if sys.platform == 'win32':
                    process.terminate()
                else:
                    process.send_signal(signal.SIGTERM)
            except (OSError, ProcessLookupError):
                pass
            # Delete the log file where error was detected
            try:
                if os.path.exists(output_log):
                    time.sleep(0.5)  # Wait for file handles to be released
                    os.remove(output_log)
                    print(f"Deleted log file: {output_log}")
            except (OSError, PermissionError) as e:
                print(f"Could not delete {output_log}: {e}")
            return True
        
        # Check error.log for rate limit error
        if check_rate_limit_error(error_log):
            print("Rate limit error detected in stderr - stopping process")
            try:
                if sys.platform == 'win32':
                    process.terminate()
                else:
                    process.send_signal(signal.SIGTERM)
            except (OSError, ProcessLookupError):
                pass
            # Delete the log file where error was detected
            try:
                if os.path.exists(error_log):
                    time.sleep(0.5)  # Wait for file handles to be released
                    os.remove(error_log)
                    print(f"Deleted log file: {error_log}")
            except (OSError, PermissionError) as e:
                print(f"Could not delete {error_log}: {e}")
            return True
    
    return False


def cleanup_log_files(output_log, error_log):
    """Remove log files if they exist."""
    for log_file in [output_log, error_log]:
        if os.path.exists(log_file):
            try:
                # Wait a bit for file handles to be released
                time.sleep(0.5)
                os.remove(log_file)
            except (OSError, PermissionError) as e:
                print(f"Could not remove {log_file}: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='Run scan with retry logic (max 5 retries)',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '--project-id',
        required=True,
        help='Project ID (required)'
    )
    parser.add_argument(
        '--model-id',
        required=True,
        help='Model ID (required)'
    )
    
    args = parser.parse_args()
    
    # Get the directory where this script is located
    script_dir = Path(__file__).parent.resolve()
    project_root = script_dir.parent.resolve()
    
    print(f"Project root: {project_root}")
    
    # Change to project root directory
    os.chdir(project_root)
    
    # Check for virtual environment and use it if it exists
    python_executable = sys.executable
    if sys.platform == 'win32':
        env_python = project_root / 'env' / 'Scripts' / 'python.exe'
    else:
        env_python = project_root / 'env' / 'bin' / 'python3'
    
    if env_python.exists() and env_python.is_file():
        python_executable = str(env_python)
        print(f"Using virtual environment Python: {python_executable}")
    else:
        print(f"Using system Python: {python_executable}")
    
    # Build command
    command = [
        python_executable,
        'run_scan.py',
        '--project-id', args.project_id,
        '--model-id', args.model_id
    ]
    
    print(f"Command: {' '.join(command)}")
    
    output_log = project_root / 'output.log'
    error_log = project_root / 'error.log'
    
    max_retries = 2
    retry_count = 0
    
    while retry_count < max_retries:
        print(f"\n=== Attempt {retry_count + 1}/{max_retries} ===")
        
        rate_limit_detected = False
        process = None
        out_file = None
        err_file = None
        
        try:
            # Open log files for writing (keep them open for subprocess)
            out_file = open(output_log, 'w', encoding='utf-8', buffering=1)
            err_file = open(error_log, 'w', encoding='utf-8', buffering=1)
            
            # Start the process with file redirection (similar to bash > output.log 2> error.log)
            process = subprocess.Popen(
                command,
                stdout=out_file,
                stderr=err_file,
                cwd=str(project_root),
                bufsize=1  # Line buffered
            )
            
            # Monitor the process (files remain open, subprocess writes to them)
            # On Unix, we can read files while they're being written
            # On Windows, we might get permission errors, but we'll keep trying
            rate_limit_detected = monitor_process(process, str(output_log), str(error_log))
            
            # Wait for process to exit completely
            try:
                process.wait()
            except (OSError, ProcessLookupError):
                pass
        
        except KeyboardInterrupt:
            print("\nInterrupted by user")
            if process:
                try:
                    if sys.platform == 'win32':
                        process.terminate()
                    else:
                        process.send_signal(signal.SIGTERM)
                    process.wait()
                except (OSError, ProcessLookupError):
                    pass
            # Close file handles
            if out_file:
                try:
                    out_file.close()
                except (IOError, OSError):
                    pass
            if err_file:
                try:
                    err_file.close()
                except (IOError, OSError):
                    pass
            sys.exit(1)
        except Exception as e:
            print(f"Error running process: {e}")
        finally:
            # Close file handles after process exits
            if out_file:
                try:
                    out_file.close()
                except (IOError, OSError):
                    pass
            if err_file:
                try:
                    err_file.close()
                except (IOError, OSError):
                    pass
        
        # Check if process exited due to rate limit
        # Also check log files one more time in case error was written after monitoring stopped
        if not rate_limit_detected:
            rate_limit_detected = check_rate_limit_error(str(output_log)) or check_rate_limit_error(str(error_log))
        
        if rate_limit_detected:
            print("Process exited due to rate limit error - waiting 10 seconds before retrying (retry count NOT incremented)")
            # Don't increment retry_count for rate limit errors
        else:
            # Only increment retry_count if process exited normally (not due to rate limit)
            retry_count += 1
            print(f"Process exited normally - waiting 10 seconds before retrying (retry count: {retry_count}/{max_retries})")
        
        # Check if we should retry
        if retry_count >= max_retries:
            print(f"\nMaximum retries ({max_retries}) reached. Exiting.")
            break
        
        # Wait before retrying
        time.sleep(10)
        
        # Clean up log files
        cleanup_log_files(str(output_log), str(error_log))
    
    # Notify Flask app that scan is complete (triggers notifications)
    try:
        import urllib.request as _urlreq, json as _json
        _project_id = int(args.project_id)
        _url = "http://localhost:8002/api/projects/" + str(_project_id) + "/scan-complete"
        _req = _urlreq.Request(
            _url,
            data=_json.dumps({}).encode(),
            headers={"Content-Type": "application/json", "X-Internal-Key": "scanner-internal"},
            method="POST"
        )
        _urlreq.urlopen(_req, timeout=5)
        print("Scan complete notification sent.")
    except Exception as _e:
        print("Could not send scan complete notification: " + str(_e))

    print("\nScript completed.")


if __name__ == '__main__':
    main()

