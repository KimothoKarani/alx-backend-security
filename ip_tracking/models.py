from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class RequestLog(models.Model):
    ip_address = models.GenericIPAddressField(
        verbose_name="IP Address",
        help_text="The IP address of the client making the request.",
    )
    timestamp = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Timestamp",
        help_text="The date and time the request was made.",
    )
    path = models.CharField(
        max_length=255,
        verbose_name="Request Path",
        help_text="The URL path of the request.",
    )
    country = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        verbose_name="Country",
        help_text="The country derived from the IP address."
    )
    city = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        verbose_name="City",
        help_text="The city derived from the IP address."
    )

    class Meta:
        verbose_name = "Request Log"
        verbose_name_plural = "Request Logs"
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.ip_address} - {self.timestamp} - {self.path} ({self.city}, {self.country})"

class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(
        unique=True,
        verbose_name="Blocked IP Address",
        help_text="An IP address that is blocked from accessing the application.",
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Blocked At",
        help_text="The date and time the IP was blocked.",
    )

    class Meta:
        verbose_name = "Blocked IP"
        verbose_name_plural = "Blocked IPs"
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.ip_address} - {self.created_at}"

class SuspiciousIP(models.Model):
    ip_address = models.GenericIPAddressField(
        unique=True,
        verbose_name="Suspicious IP Address",
        help_text="An IP address flagged for suspicious activity."
    )
    reason = models.TextField(
        verbose_name="Reason",
        help_text="Reason(s) why this IP was flagged as suspicious."
    )
    flagged_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Flagged At",
        help_text="The date and time the IP was flagged."
    )
    is_resolved = models.BooleanField(
        default=False,
        verbose_name="Is Resolved",
        help_text="Indicates if the suspicious activity has been investigated and resolved."
    )

    class Meta:
        verbose_name = "Suspicious IP"
        verbose_name_plural = "Suspicious IPs"
        ordering = ['-flagged_at']

    def __str__(self):
        return f"{self.ip_address} - {self.reason[:50]}..." # Show first 50 chars of reason