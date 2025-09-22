#!/bin/bash
# filepath: /Users/yuri/dev/gin525-pytool/scripts/run_tls_scan_cron_simple.sh

# Configuration
PROJECT_DIR="/Users/yuri/dev/gin525-pytool"
VENV_PATH="$PROJECT_DIR/env"
LOG_FILE="$HOME/tls_scanner.log"
LOCK_FILE="/tmp/tls_scan.lock"

# Function to log messages
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S'): $1" >> "$LOG_FILE"
}

# Check if another instance is running
if [ -f "$LOCK_FILE" ]; then
    log_message "Another TLS scan is already running. Exiting."
    exit 1
fi

# Create lock file
echo $$ > "$LOCK_FILE"

# Cleanup function
cleanup() {
    rm -f "$LOCK_FILE"
}

# Set trap to cleanup on exit
trap cleanup EXIT

# Set full environment for cron
export HOME="/Users/yuri"
export USER="yuri"
export PATH="/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin"
export DJANGO_SETTINGS_MODULE=gin525.settings
export PYTHONPATH="$PROJECT_DIR"

# Change to project directory
cd "$PROJECT_DIR" || {
    log_message "ERROR: Failed to change to project directory $PROJECT_DIR"
    exit 1
}

# Find Python executable
PYTHON_EXE="$VENV_PATH/bin/python"

if [ ! -f "$PYTHON_EXE" ]; then
    log_message "ERROR: Python executable not found at $PYTHON_EXE"
    exit 1
fi

log_message "Starting TLS scan"

# Run the Django management command directly (no timeout)
"$PYTHON_EXE" manage.py run_tls_scan --config-name=default --verbose >> "$LOG_FILE" 2>&1
exit_code=$?

if [ $exit_code -eq 0 ]; then
    log_message "TLS scan completed successfully"
else
    log_message "ERROR: TLS scan failed with exit code $exit_code"
fi

exit $exit_code