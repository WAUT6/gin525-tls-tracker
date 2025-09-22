# TLS Certificate Tracker

A Django-based system for monitoring TLS certificates and SSL configurations across multiple endpoints. The system provides automated scanning, change detection, and email notifications for SSL/TLS certificate changes and expirations.

## Features

- **Automated TLS Scanning**: Periodic scanning of TLS endpoints to monitor certificate status
- **Change Detection**: Detects changes in certificates, protocols, cipher suites, and other SSL configurations
- **Email Notifications**: Automated alerts for certificate changes and upcoming expirations
- **Self-Signed Certificate Support**: Handles self-signed certificates without failing
- **Multiple Fallback Methods**: Robust scanning with multiple connection methods for problematic endpoints
- **Web Interface**: REST API for managing endpoints and viewing scan results
- **Cron Integration**: Automated scheduling via cron jobs

## System Architecture

```
TLS Tracker System
├── Django Web Application
├── TLS Scanner (with fallback methods)
├── Change Detection Engine
├── Email Notification Service
└── Cron Job Scheduler
```

## Installation

### Prerequisites

- Python 3.8+
- Django 5.2+
- Virtual environment (recommended)

### Setup

1. **Clone or setup the project:**
```bash
cd /Users/yuri/dev/gin525-pytool
```

2. **Create and activate virtual environment:**
```bash
python3 -m venv env
source env/bin/activate
```

3. **Install dependencies:**
```bash
pip install django djangorestframework cryptography pytz
```

4. **Configure Django settings:**
```python
# In gin525/settings.py
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'tls_tracker',
    'rest_framework',
]

# Email configuration (adjust for your provider)
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp-mail.outlook.com'  # For Outlook/Hotmail
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'your-email@example.com'
EMAIL_HOST_PASSWORD = 'your-app-password'
DEFAULT_FROM_EMAIL = 'TLS Tracker <your-email@example.com>'
```

5. **Run migrations:**
```bash
python manage.py makemigrations
python manage.py migrate
```

6. **Create superuser:**
```bash
python manage.py createsuperuser
```

## Configuration

### 1. Add TLS Endpoints

Access Django admin at `http://localhost:8000/admin/` and add TLS endpoints to monitor:

- **Domain**: The hostname to monitor (e.g., `google.com`, `localhost`)
- **Port**: The port number (default: 443)
- **Active**: Whether to include in scans

### 2. Configure Scan Settings

Create a `ScanConfiguration` in Django admin:

- **Name**: Configuration name (e.g., "default")
- **Active Configuration**: Mark as active
- **Certificate Expiry Warning Days**: Days before expiration to alert (default: 30)
- **Enable Email Alerts**: Whether to send email notifications
- **Alert Emails**: Comma-separated list of email addresses

## Cron Job Setup

### 1. Make the script executable:
```bash
chmod +x /Users/yuri/dev/gin525-pytool/scripts/run_tls_scan_cron.sh
```

### 2. Test the script manually:
```bash
# Test the script
/Users/yuri/dev/gin525-pytool/scripts/run_tls_scan_cron.sh

# Check the log output
tail -f ~/tls_scanner.log
```

### 3. Set up cron job:
```bash
# Edit crontab
crontab -e

# Add cron jobs (choose frequency as needed):

# Every minute
* * * * * /bin/bash /Users/yuri/dev/gin525-pytool/scripts/run_tls_scan_cron.sh

# Every 5 minutes
*/5 * * * * /bin/bash /Users/yuri/dev/gin525-pytool/scripts/run_tls_scan_cron.sh

# Every 15 minutes 
*/15 * * * * /bin/bash /Users/yuri/dev/gin525-pytool/scripts/run_tls_scan_cron.sh

# Every hour
0 * * * * /bin/bash /Users/yuri/dev/gin525-pytool/scripts/run_tls_scan_cron.sh

# Daily at 2 AM
0 2 * * * /bin/bash /Users/yuri/dev/gin525-pytool/scripts/run_tls_scan_cron.sh
```

### 4. Monitor cron execution:
```bash
# View cron logs
tail -f ~/tls_scanner.log

# Check if cron jobs are running
ps aux | grep run_tls_scan

# View current crontab
crontab -l
```

## Manual Operations

### Run TLS Scan Manually
```bash
cd /Users/yuri/dev/gin525-pytool
source env/bin/activate
python manage.py run_tls_scan --config-name=default --verbose
```

### Test Individual Endpoints
```bash
# Via management command
python manage.py shell

# In Django shell:
from tls_tracker.scanner import scanner
result = scanner.scan_endpoint('google.com', 443)
print(result)
```

### API Endpoints

The system provides REST API endpoints:

- `POST /tls_tracker/scan/` - Trigger manual scan
- `POST /tls_tracker/test/` - Test individual endpoint
- `GET /tls_tracker/results/` - Get scan results
- `GET /tls_tracker/changes/` - Get detected changes
- `POST /tls_tracker/changes/<id>/acknowledge/` - Acknowledge changes

Example API usage:
```bash
# Test an endpoint
curl -X POST http://localhost:8000/tls_tracker/test/ \
  -H "Content-Type: application/json" \
  -d '{"hostname": "google.com", "port": 443}'

# Trigger a scan
curl -X POST http://localhost:8000/tls_tracker/scan/

# Get recent results
curl http://localhost:8000/tls_tracker/results/?limit=10
```

### Debug Commands

```bash
# Test cron environment
env - HOME=/Users/yuri /bin/bash /Users/yuri/dev/gin525-pytool/scripts/run_tls_scan_cron.sh

# Check virtual environment
ls -la /Users/yuri/dev/gin525-pytool/env/bin/python

# Test Django setup
cd /Users/yuri/dev/gin525-pytool
source env/bin/activate
python -c "import django; django.setup(); print('Django OK')"

# Test database connection
python manage.py shell -c "from django.db import connection; connection.ensure_connection(); print('DB OK')"
```

### Log Files

- **Cron execution log**: `~/tls_scanner.log`
- **Django application logs**: Check Django logging configuration
- **System cron logs**: `/var/log/system.log` (macOS)

## Email Setup

### Gmail Configuration

1. Enable 2-factor authentication
2. Go to https://myaccount.google.com/apppasswords
3. Generate an app password for "Mail"
4. Use Gmail SMTP settings:
   ```python
   EMAIL_HOST = 'smtp.gmail.com'
   EMAIL_PORT = 587
   EMAIL_USE_TLS = True
   ```