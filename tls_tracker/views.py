from django.utils import timezone
from rest_framework.response import Response
from rest_framework.decorators import api_view
from django.views.decorators.http import require_http_methods
from django.http import JsonResponse
import logging

from tls_tracker.scanner import scanner
from tls_tracker.change_detector import change_detector
from tls_tracker.email_service import email_service
from tls_tracker.models import (
    TLSEndpoint,
    EndpointScanResult,
    ScanJob,
    ScanConfiguration,
    ChangeDetection,
)

logger = logging.getLogger(__name__)


def _create_scan_job(configuration):
    """Create a new scan job"""
    scan_job = ScanJob.objects.create(
        configuration=configuration, status="running", started_at=timezone.now()
    )
    return scan_job


@require_http_methods(["POST"])
def scan_endpoints(request):
    """Scan all active endpoints for TLS configuration"""

    # Get active configuration
    configuration = ScanConfiguration.objects.filter(
        is_active_configuration=True
    ).first()

    if not configuration:
        return JsonResponse(
            {"error": "No active scan configuration found."}, status=400
        )

    # Create scan job
    scan_job = _create_scan_job(configuration)

    # Get active endpoints
    endpoints = TLSEndpoint.objects.filter(is_active=True)
    if not endpoints.exists():
        scan_job.status = "failed"
        scan_job.errors = "No active endpoints to scan."
        scan_job.completed_at = timezone.now()
        scan_job.save()
        return JsonResponse({"error": "No active endpoints to scan."}, status=400)

    results = []
    total_changes = 0
    all_changes = []  # Collect all changes for email

    try:
        for endpoint in endpoints:
            logger.info(f"Scanning endpoint: {endpoint.domain}:{endpoint.port}")

            # Perform TLS scan
            scan_data = scanner.scan_endpoint(endpoint.domain, endpoint.port)

            if not scan_data.get("success"):
                logger.error(
                    f"Scan failed for {endpoint.domain}:{endpoint.port}: {scan_data.get('error')}"
                )
                continue

            # Create scan result
            scan_result = EndpointScanResult.objects.create(
                endpoint=endpoint,
                cert_subject=scan_data["cert_subject"],
                cert_issuer=scan_data["cert_issuer"],
                cert_expiration=scan_data["cert_expiration"],
                cert_serial_number=scan_data["cert_serial_number"],
                cert_chain_length=scan_data["cert_chain_length"],
                cert_chain_raw=scan_data["cert_chain_raw"],
                protocol_version=scan_data["protocol_version"],
                cipher_suite=scan_data["cipher_suite"],
                key_exchange=scan_data.get("key_exchange", ""),
                uses_ephemeral_keys=scan_data.get("uses_ephemeral_keys", False),
                is_valid=scan_data["is_valid"],
                validation_errors=scan_data.get("validation_errors", ""),
                is_self_signed=scan_data.get("is_self_signed", False),
            )

            # Update endpoint last_checked
            endpoint.last_checked = timezone.now()
            endpoint.save()

            # Detect changes
            previous_scan = scan_result.get_previous_result()
            changes = change_detector.detect_changes(scan_result, previous_scan)

            # Check for certificate expiry
            expiry_change = change_detector.check_certificate_expiry(
                scan_result, configuration.cert_expiry_warning_days
            )
            if expiry_change:
                changes.append(expiry_change)

            # Save detected changes
            for change in changes:
                change.save()
                total_changes += 1
                all_changes.append(change)
                logger.warning(f"Change detected: {change.description}")

            # Update scan job counters
            scan_job.endpoints_scanned += 1
            scan_job.save()

            # Prepare result summary
            result_summary = {
                "endpoint": f"{endpoint.domain}:{endpoint.port}",
                "protocol_version": scan_data["protocol_version"],
                "cipher_suite": scan_data["cipher_suite"],
                "cert_expiration": (
                    scan_data["cert_expiration"].isoformat()
                    if scan_data["cert_expiration"]
                    else None
                ),
                "is_valid": scan_data["is_valid"],
                "changes_detected": len(changes),
            }
            results.append(result_summary)

        # Complete scan job
        scan_job.status = "completed"
        scan_job.completed_at = timezone.now()
        scan_job.changes_detected = total_changes
        scan_job.save()

        # Send email alerts if changes were detected
        if all_changes:
            email_service.send_change_alert(all_changes, scan_job, configuration)

        # Send scan summary email (optional)
        email_service.send_scan_summary(scan_job, configuration)

        logger.info(
            f"Scan completed. Scanned {scan_job.endpoints_scanned} endpoints, detected {total_changes} changes"
        )

        return JsonResponse(
            {
                "message": "Scan completed successfully",
                "job_id": scan_job.id,
                "endpoints_scanned": scan_job.endpoints_scanned,
                "changes_detected": total_changes,
                "results": results,
            }
        )

    except Exception as e:
        logger.error(f"Scan job failed: {str(e)}")
        scan_job.status = "failed"
        scan_job.errors = str(e)
        scan_job.completed_at = timezone.now()
        scan_job.save()

        return JsonResponse({"error": f"Scan failed: {str(e)}"}, status=500)


# ...rest of the views remain the same...
@api_view(["GET"])
def get_scan_results(request):
    """Get recent scan results"""
    limit = int(request.GET.get("limit", 50))
    endpoint_domain = request.GET.get("domain")

    queryset = EndpointScanResult.objects.select_related("endpoint")

    if endpoint_domain:
        queryset = queryset.filter(endpoint__domain=endpoint_domain)

    results = queryset[:limit]

    data = []
    for result in results:
        data.append(
            {
                "id": result.id,
                "endpoint": f"{result.endpoint.domain}:{result.endpoint.port}",
                "scan_date": result.scan_date.isoformat(),
                "protocol_version": result.protocol_version,
                "cipher_suite": result.cipher_suite,
                "cert_expiration": (
                    result.cert_expiration.isoformat()
                    if result.cert_expiration
                    else None
                ),
                "is_valid": result.is_valid,
                "uses_ephemeral_keys": result.uses_ephemeral_keys,
            }
        )

    return Response({"results": data})


@api_view(["GET"])
def get_changes(request):
    """Get recent changes detected"""
    limit = int(request.GET.get("limit", 50))
    severity = request.GET.get("severity")
    acknowledged = request.GET.get("acknowledged")

    queryset = ChangeDetection.objects.select_related("endpoint", "scan_result")

    if severity:
        queryset = queryset.filter(severity=severity)

    if acknowledged is not None:
        queryset = queryset.filter(acknowledged=acknowledged.lower() == "true")

    changes = queryset[:limit]

    data = []
    for change in changes:
        data.append(
            {
                "id": change.id,
                "endpoint": f"{change.endpoint.domain}:{change.endpoint.port}",
                "change_type": change.get_change_type_display(),
                "severity": change.get_severity_display(),
                "description": change.description,
                "detected_at": change.detected_at.isoformat(),
                "acknowledged": change.acknowledged,
                "previous_value": change.previous_value,
                "new_value": change.new_value,
            }
        )

    return Response({"changes": data})


@api_view(["POST"])
def acknowledge_change(request, change_id):
    """Acknowledge a detected change"""
    try:
        change = ChangeDetection.objects.get(id=change_id)
        change.acknowledged = True
        change.acknowledged_at = timezone.now()
        change.save()

        return Response({"message": "Change acknowledged successfully"})
    except ChangeDetection.DoesNotExist:
        return Response({"error": "Change not found"}, status=404)
