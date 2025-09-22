from django.contrib import admin

from tls_tracker.models import (
    ChangeDetection,
    ScanConfiguration,
    ScanJob,
    TLSEndpoint,
    EndpointScanResult,
)

# Register your models here.
admin.site.register(TLSEndpoint)
admin.site.register(EndpointScanResult)
admin.site.register(ScanConfiguration)
admin.site.register(ScanJob)
admin.site.register(ChangeDetection)
