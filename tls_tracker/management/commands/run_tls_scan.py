from django.core.management.base import BaseCommand
from django.utils import timezone
from django.http import HttpRequest
from django.db import transaction
from django.conf import settings
import logging
import sys
import os

from tls_tracker.views import scan_endpoints
from tls_tracker.models import ScanConfiguration, ScanJob

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Run TLS scan for all active endpoints"

    def add_arguments(self, parser):
        parser.add_argument(
            "--config-name",
            type=str,
            default="default",
            help="Name of the scan configuration to use",
        )
        parser.add_argument(
            "--force",
            action="store_true",
            help="Force scan even if one is already running",
        )
        parser.add_argument(
            "--verbose",
            action="store_true",
            help="Enable verbose output",
        )

    def handle(self, *args, **options):
        config_name = options["config_name"]
        force = options["force"]
        verbose = options["verbose"]

        if verbose:
            self.stdout.write(f"=== TLS Scan Debug Info ===")
            self.stdout.write(
                f"Django settings module: {os.environ.get('DJANGO_SETTINGS_MODULE')}"
            )
            self.stdout.write(f"Database: {settings.DATABASES['default']}")
            self.stdout.write(f"Time zone: {settings.TIME_ZONE}")
            self.stdout.write(f"Current time: {timezone.now()}")

        self.stdout.write(f"Starting TLS scan at {timezone.now()}")

        try:
            # Test database connection
            from django.db import connection

            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")

            if verbose:
                self.stdout.write("Database connection: OK")

        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Database connection failed: {str(e)}"))
            return

        # Check if a scan is already running (unless forced)
        if not force:
            try:
                running_jobs = ScanJob.objects.filter(status="running")
                if running_jobs.exists():
                    self.stdout.write(
                        self.style.WARNING(
                            f"Scan job already running (ID: {running_jobs.first().id}). "
                            "Use --force to override."
                        )
                    )
                    return
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f"Failed to check running jobs: {str(e)}")
                )
                return

        try:
            # Get configuration
            configuration = ScanConfiguration.objects.filter(
                is_active_configuration=True, name=config_name
            ).first()

            if not configuration:
                self.stdout.write(
                    self.style.ERROR(
                        f"No active scan configuration found with name: {config_name}"
                    )
                )
                return

            if verbose:
                self.stdout.write(f"Using configuration: {configuration}")

            # Create a mock request object
            request = HttpRequest()
            request.method = "POST"
            request.POST = {"config_name": config_name}

            # Run the scan
            self.stdout.write("Calling scan_endpoints...")
            response = scan_endpoints(request)

            if response.status_code == 200:
                response_data = response.content.decode("utf-8")
                self.stdout.write(
                    self.style.SUCCESS(
                        f"TLS scan completed successfully: {response_data}"
                    )
                )
            else:
                error_content = (
                    response.content.decode("utf-8")
                    if response.content
                    else "No error details"
                )
                self.stdout.write(
                    self.style.ERROR(
                        f"TLS scan failed with status {response.status_code}: {error_content}"
                    )
                )
                sys.exit(1)

        except Exception as e:
            import traceback

            error_details = traceback.format_exc()
            logger.error(f"TLS scan command failed: {str(e)}\n{error_details}")
            self.stdout.write(
                self.style.ERROR(f"TLS scan failed: {str(e)}\nDetails: {error_details}")
            )
            sys.exit(1)
