# ip_tracking/admin.py

from django.contrib import admin
from .models import RequestLog, BlockedIP, SuspiciousIP

@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'timestamp', 'path', 'country', 'city')
    search_fields = ('ip_address', 'path', 'country', 'city')
    list_filter = ('timestamp', 'country', 'city')
    readonly_fields = ('ip_address', 'timestamp', 'path', 'country', 'city')

@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'created_at')
    search_fields = ('ip_address',)

@admin.register(SuspiciousIP)
class SuspiciousIPAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'reason', 'flagged_at', 'is_resolved')
    list_filter = ('is_resolved', 'flagged_at')
    search_fields = ('ip_address', 'reason')
    list_editable = ('is_resolved',) # Allows changing 'is_resolved' directly from list view
    list_per_page = 25