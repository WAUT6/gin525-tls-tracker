from datetime import timedelta
from django.utils import timezone
from .models import ChangeDetection, EndpointScanResult
import logging

logger = logging.getLogger(__name__)


class ChangeDetector:
    def __init__(self):
        self.severity_mapping = {
            "protocol_downgrade": "high",
            "cipher_change": "medium",
            "cert_change": "medium",
            "cert_expiring": "high",
            "ephemeral_keys_lost": "high",
            "validation_failed": "critical",
        }

    def detect_changes(self, current_scan, previous_scan=None):
        """Detect changes between current and previous scan results"""
        changes = []

        if not previous_scan:
            # No previous scan to compare with
            return changes

        # Check for protocol downgrade
        if self._is_protocol_downgrade(
            current_scan.protocol_version, previous_scan.protocol_version
        ):
            changes.append(
                self._create_change(
                    current_scan,
                    "protocol_downgrade",
                    f"Protocol downgraded from {previous_scan.protocol_version} to {current_scan.protocol_version}",
                    previous_scan.protocol_version,
                    current_scan.protocol_version,
                )
            )

        # Check for cipher suite changes
        if current_scan.cipher_suite != previous_scan.cipher_suite:
            changes.append(
                self._create_change(
                    current_scan,
                    "cipher_change",
                    f"Cipher suite changed from {previous_scan.cipher_suite} to {current_scan.cipher_suite}",
                    previous_scan.cipher_suite,
                    current_scan.cipher_suite,
                )
            )

        # Check for loss of ephemeral keys
        if previous_scan.uses_ephemeral_keys and not current_scan.uses_ephemeral_keys:
            changes.append(
                self._create_change(
                    current_scan,
                    "ephemeral_keys_lost",
                    "Endpoint no longer uses ephemeral key exchange",
                    "True",
                    "False",
                )
            )

        # Check for certificate changes
        if current_scan.cert_serial_number != previous_scan.cert_serial_number:
            changes.append(
                self._create_change(
                    current_scan,
                    "cert_change",
                    f"Certificate changed (serial: {previous_scan.cert_serial_number} -> {current_scan.cert_serial_number})",
                    previous_scan.cert_serial_number,
                    current_scan.cert_serial_number,
                )
            )

        # Check for validation failures
        if (
            current_scan.is_valid != previous_scan.is_valid
            and not current_scan.is_valid
        ):
            changes.append(
                self._create_change(
                    current_scan,
                    "validation_failed",
                    f"Validation failed: {current_scan.validation_errors}",
                    "Valid",
                    "Invalid",
                )
            )

        return changes

    def check_certificate_expiry(self, scan_result, warning_days=30):
        """Check if certificate is expiring soon"""
        if not scan_result.cert_expiration:
            return None

        # Ensure we're working with timezone-aware datetimes
        now = timezone.now()
        warning_date = now + timedelta(days=warning_days)

        if scan_result.cert_expiration <= warning_date:
            # Calculate days until expiry
            days_until_expiry = (scan_result.cert_expiration - now).days
            return self._create_change(
                scan_result,
                "cert_expiring",
                f"Certificate expires in {days_until_expiry} days",
                "",
                str(days_until_expiry),
            )
        return None

    def _is_protocol_downgrade(self, current_version, previous_version):
        """Check if current version is a downgrade from previous"""
        version_order = {
            "TLSv1.3": 4,
            "TLSv1.2": 3,
            "TLSv1.1": 2,
            "TLSv1.0": 1,
            "TLSv1": 1,
            "SSLv3": 0,
            "SSLv2": -1,
        }

        current_score = version_order.get(current_version, 0)
        previous_score = version_order.get(previous_version, 0)

        return current_score < previous_score

    def _create_change(
        self, scan_result, change_type, description, previous_value, new_value
    ):
        """Create a ChangeDetection object"""
        return ChangeDetection(
            endpoint=scan_result.endpoint,
            scan_result=scan_result,
            change_type=change_type,
            severity=self.severity_mapping.get(change_type, "medium"),
            previous_value=previous_value,
            new_value=new_value,
            description=description,
        )


# Create a default detector instance
change_detector = ChangeDetector()
