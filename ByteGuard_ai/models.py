from django.db import models


class OmniScan(models.Model):
    TARGET_TYPES = [
        ('WEBSITE', 'Website / Web Application'),
        ('SYSTEM', 'System Network or Source Code'),
        ('HARDWARE', 'Hardware Firmware Binaries'),
    ]

    STATUS_CHOICES = [
        ('PENDING', 'Pending Assessment'),
        ('SCANNING', 'Running System Probes'),
        ('ANALYZING', 'AI Evaluation & Planning'),
        ('FIXING', 'Applying Patches'),
        ('COMPLETED', 'System Secured'),
        ('FAILED', 'Scan / Fix Failed'),
    ]

    target_type = models.CharField(max_length=20, choices=TARGET_TYPES)
    target_identifier = models.CharField(
        max_length=512,
        help_text='URL, IP Address, Directory Path, or Firmware File Path',
    )
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='PENDING')

    raw_probe_output = models.TextField(
        blank=True,
        null=True,
        help_text='Raw outputs from Nmap/ZAP/Binwalk',
    )
    vulnerabilities_found = models.TextField(
        blank=True,
        null=True,
        help_text='AI-listed security gaps',
    )
    remediation_plan = models.TextField(
        blank=True,
        null=True,
        help_text='Step-by-step fix strategy created by AI',
    )
    execution_script = models.TextField(
        blank=True,
        null=True,
        help_text='AI-generated bash/python script to deploy the fix',
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"[{self.target_type}] {self.target_identifier} - {self.status}"
