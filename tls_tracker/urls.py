from django.urls import path
from . import views

urlpatterns = [
    path("scan/", views.scan_endpoints, name="scan_endpoints"),
    path("results/", views.get_scan_results, name="get_scan_results"),
    path("changes/", views.get_changes, name="get_changes"),
    path(
        "changes/<int:change_id>/acknowledge/",
        views.acknowledge_change,
        name="acknowledge_change",
    ),
]
