from django.db import models


class TLSEndpoint(models.Model):
    domain = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField()
    port = models.PositiveIntegerField(default=443)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_checked = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ["domain", "port"]

    def __str__(self):
        return f"{self.domain}:{self.port} ({self.ip_address})"


class EndpointScanResult(models.Model):
    endpoint = models.ForeignKey(
        TLSEndpoint, on_delete=models.CASCADE, related_name="scan_results"
    )
    scan_date = models.DateTimeField(auto_now_add=True)

    is_self_signed = models.BooleanField(default=False)

    # Certificate information
    cert_subject = models.TextField()
    cert_issuer = models.TextField()
    cert_expiration = models.DateTimeField()
    cert_serial_number = models.CharField(max_length=100)
    cert_chain_length = models.PositiveIntegerField(default=1)
    cert_chain_raw = models.TextField()  # Store full chain for detailed analysis

    # TLS configuration
    protocol_version = models.CharField(max_length=50)
    cipher_suite = models.CharField(max_length=100)
    key_exchange = models.CharField(max_length=50, blank=True)
    uses_ephemeral_keys = models.BooleanField(default=False)

    # Validation status
    is_valid = models.BooleanField(default=False)
    validation_errors = models.TextField(blank=True)

    class Meta:
        ordering = ["-scan_date"]

    def __str__(self):
        return f"ScanResult for {self.endpoint.domain} on {self.scan_date}"

    def get_previous_result(self):
        """Get the previous scan result for comparison"""
        return EndpointScanResult.objects.filter(
            endpoint=self.endpoint, scan_date__lt=self.scan_date
        ).first()


class ChangeDetection(models.Model):
    CHANGE_TYPES = [
        ("protocol_downgrade", "Protocol Downgrade"),
        ("cipher_change", "Cipher Suite Change"),
        ("cert_change", "Certificate Change"),
        ("cert_expiring", "Certificate Expiring Soon"),
        ("ephemeral_keys_lost", "Lost Ephemeral Key Exchange"),
        ("validation_failed", "Validation Failed"),
    ]

    SEVERITY_LEVELS = [
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    ]

    endpoint = models.ForeignKey(
        TLSEndpoint, on_delete=models.CASCADE, related_name="changes"
    )
    scan_result = models.ForeignKey(EndpointScanResult, on_delete=models.CASCADE)
    change_type = models.CharField(max_length=50, choices=CHANGE_TYPES)
    severity = models.CharField(
        max_length=10, choices=SEVERITY_LEVELS, default="medium"
    )

    previous_value = models.TextField(blank=True)
    new_value = models.TextField(blank=True)
    description = models.TextField()

    detected_at = models.DateTimeField(auto_now_add=True)
    acknowledged = models.BooleanField(default=False)
    acknowledged_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-detected_at"]

    def __str__(self):
        return f"{self.get_change_type_display()} for {self.endpoint.domain} - {self.severity}"


class ScanConfiguration(models.Model):
    """Configuration for scanning behavior"""

    name = models.CharField(max_length=100, unique=True, default="default")
    scan_interval_hours = models.PositiveIntegerField(default=24)
    timeout_seconds = models.PositiveIntegerField(default=30)
    is_active_configuration = models.BooleanField(default=True)

    # Alert thresholds
    cert_expiry_warning_days = models.PositiveIntegerField(default=30)
    enable_email_alerts = models.BooleanField(default=False)
    alert_email_addresses = models.TextField(
        blank=True, help_text="Comma-separated email addresses"
    )

    # Protocol preferences
    min_tls_version = models.CharField(max_length=10, default="1.2")
    require_ephemeral_keys = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Scan Config: {self.name}"

    def get_alert_emails(self):
        """Return list of email addresses for alerts"""
        if self.alert_email_addresses:
            return [email.strip() for email in self.alert_email_addresses.split(",")]
        return []


class ScanJob(models.Model):
    """Track scan job execution"""

    JOB_STATUS = [
        ("pending", "Pending"),
        ("running", "Running"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    ]

    configuration = models.ForeignKey(ScanConfiguration, on_delete=models.CASCADE)
    status = models.CharField(max_length=20, choices=JOB_STATUS, default="pending")

    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    endpoints_scanned = models.PositiveIntegerField(default=0)
    changes_detected = models.PositiveIntegerField(default=0)
    errors = models.TextField(blank=True)

    class Meta:
        ordering = ["-started_at"]

    def __str__(self):
        return f"Scan Job {self.pk} - {self.status}"

    @property
    def duration(self):
        """Calculate job duration"""
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return None
