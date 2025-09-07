from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count, Q  # Import Q for complex lookups
from .models import RequestLog, SuspiciousIP
import logging

logger = logging.getLogger(__name__)


@shared_task
def detect_anomalies():
    logger.info("Starting anomaly detection task...")
    now = timezone.now()
    one_hour_ago = now - timedelta(hours=1)

    # --- Criteria 1: IPs exceeding 100 requests/hour ---
    high_traffic_ips = RequestLog.objects.filter(
        timestamp__gte=one_hour_ago
    ).values('ip_address').annotate(
        request_count=Count('ip_address')
    ).filter(
        request_count__gt=100
    )

    for entry in high_traffic_ips:
        ip = entry['ip_address']
        count = entry['request_count']
        reason_high_traffic = f"Exceeded {count} requests in the last hour (threshold: 100)."

        # Get or create the SuspiciousIP entry
        suspicious_entry, created = SuspiciousIP.objects.get_or_create(
            ip_address=ip,
            defaults={'reason': reason_high_traffic}
        )
        if not created and reason_high_traffic not in suspicious_entry.reason:
            # If it already existed and this reason is new, append it
            suspicious_entry.reason += f"; {reason_high_traffic}"
            suspicious_entry.is_resolved = False  # Re-flag if activity persists
            suspicious_entry.save()

        logger.warning(f"Flagged IP {ip} for high traffic: {reason_high_traffic}")

    # --- Criteria 2: IPs accessing sensitive paths ---
    # Define sensitive path patterns. Using Q objects for flexible 'OR' conditions.
    sensitive_path_queries = (
            Q(path__startswith='/admin/') |  # Django admin paths
            Q(path__startswith='/login/') |  # Common login path
            Q(path__startswith='/accounts/login/') |  # Another common login path
            Q(path__startswith='/api/v1/auth/login/') |  # Example API login path
            Q(path__startswith='/ip-tracking/sensitive-login/')  # Our example from Task 3
    )

    sensitive_access_ips = RequestLog.objects.filter(
        timestamp__gte=one_hour_ago
    ).filter(
        sensitive_path_queries
    ).values_list('ip_address', flat=True).distinct()

    for ip in sensitive_access_ips:
        reason_sensitive_access = "Accessed sensitive path(s) in the last hour."

        suspicious_entry, created = SuspiciousIP.objects.get_or_create(
            ip_address=ip,
            defaults={'reason': reason_sensitive_access}
        )
        if not created and reason_sensitive_access not in suspicious_entry.reason:
            # If it already existed and this reason is new, append it
            suspicious_entry.reason += f"; {reason_sensitive_access}"
            suspicious_entry.is_resolved = False  # Re-flag if activity persists
            suspicious_entry.save()

        logger.warning(f"Flagged IP {ip} for sensitive path access.")

    logger.info("Anomaly detection task finished.")