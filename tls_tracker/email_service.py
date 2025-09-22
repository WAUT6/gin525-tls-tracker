from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags
import logging

logger = logging.getLogger(__name__)


class EmailAlertService:
    def __init__(self):
        self.from_email = getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@example.com")

    def send_change_alert(self, changes, scan_job, configuration):
        """Send email alert when changes are detected"""
        if not configuration.enable_email_alerts:
            logger.info("Email alerts are disabled in configuration")
            return False

        email_addresses = configuration.get_alert_emails()
        if not email_addresses:
            logger.warning("No email addresses configured for alerts")
            return False

        # Group changes by severity
        critical_changes = [c for c in changes if c.severity == "critical"]
        high_changes = [c for c in changes if c.severity == "high"]
        medium_changes = [c for c in changes if c.severity == "medium"]
        low_changes = [c for c in changes if c.severity == "low"]

        # Determine email priority based on highest severity
        if critical_changes:
            priority = "CRITICAL"
        elif high_changes:
            priority = "HIGH"
        elif medium_changes:
            priority = "MEDIUM"
        else:
            priority = "LOW"

        subject = f"[{priority}] TLS Configuration Changes Detected - {len(changes)} change(s)"

        # Create email context
        context = {
            "scan_job": scan_job,
            "configuration": configuration,
            "critical_changes": critical_changes,
            "high_changes": high_changes,
            "medium_changes": medium_changes,
            "low_changes": low_changes,
            "total_changes": len(changes),
            "priority": priority,
        }

        try:
            # Render HTML email template
            html_message = render_to_string("emails/change_alert.html", context)
            plain_message = strip_tags(html_message)

            # Send email
            send_mail(
                subject=subject,
                message=plain_message,
                from_email=self.from_email,
                recipient_list=email_addresses,
                html_message=html_message,
                fail_silently=False,
            )

            logger.info(f"Change alert email sent to {len(email_addresses)} recipients")
            return True

        except Exception as e:
            logger.error(f"Failed to send change alert email: {str(e)}")
            return False

    def send_scan_summary(self, scan_job, configuration):
        """Send daily/periodic scan summary"""
        if not configuration.enable_email_alerts:
            return False

        email_addresses = configuration.get_alert_emails()
        if not email_addresses:
            return False

        subject = f"TLS Scan Summary - {scan_job.endpoints_scanned} endpoints scanned"

        context = {
            "scan_job": scan_job,
            "configuration": configuration,
        }

        try:
            html_message = render_to_string("emails/scan_summary.html", context)
            plain_message = strip_tags(html_message)

            send_mail(
                subject=subject,
                message=plain_message,
                from_email=self.from_email,
                recipient_list=email_addresses,
                html_message=html_message,
                fail_silently=False,
            )

            logger.info(f"Scan summary email sent to {len(email_addresses)} recipients")
            return True

        except Exception as e:
            logger.error(f"Failed to send scan summary email: {str(e)}")
            return False


# Create a default email service instance
email_service = EmailAlertService()
