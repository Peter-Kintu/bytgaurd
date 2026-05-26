from django.contrib import admin
from django.utils.html import format_html

from .models import OmniScan


@admin.register(OmniScan)
class OmniScanAdmin(admin.ModelAdmin):
    list_display = ('target_identifier', 'target_type', 'colored_status', 'created_at')
    list_filter = ('target_type', 'status')
    readonly_fields = ('created_at', 'updated_at')

    def colored_status(self, obj):
        colors = {
            'PENDING': 'gray',
            'SCANNING': 'orange',
            'ANALYZING': 'blue',
            'FIXING': 'purple',
            'COMPLETED': 'green',
            'FAILED': 'red',
        }
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            colors.get(obj.status, 'black'),
            obj.status,
        )

    colored_status.short_description = 'Scan Status'
