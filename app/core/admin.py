from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin

from .models import AuditLog, Finding, KnowledgeBase, Report, User


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    fieldsets = DjangoUserAdmin.fieldsets + (
        ("Security", {"fields": ("role", "mfa_required", "mfa_enrolled")}),
    )
    list_display = ("username", "email", "role", "is_staff", "is_active", "mfa_enrolled")
    list_filter = ("role", "is_staff", "is_active", "mfa_enrolled")


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ("title", "client", "report_date", "status", "author")
    list_filter = ("status", "report_date")
    search_fields = ("title", "client", "author__username")


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ("title", "report", "cvss_score", "owasp_category")
    list_filter = ("owasp_category",)
    search_fields = ("title", "report__title")


@admin.register(KnowledgeBase)
class KnowledgeBaseAdmin(admin.ModelAdmin):
    list_display = ("title", "cwe", "updated_at")
    list_filter = ("cwe",)
    search_fields = ("title", "cwe")


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("timestamp", "user", "action", "object_type", "object_id", "ip_address")
    list_filter = ("action", "timestamp")
    search_fields = ("user__username", "object_type", "object_id", "ip_address")
    readonly_fields = ("timestamp",)
