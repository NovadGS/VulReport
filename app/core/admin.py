from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin

from .models import (
    AuditLog,
    Finding,
    KnowledgeBase,
    Report,
    TopDevice,
    User,
    WebAuthnCredential,
)


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    fieldsets = DjangoUserAdmin.fieldsets + (
        ("Security", {"fields": ("role", "mfa_required", "mfa_enrolled", "top_enabled")}),
    )
    list_display = ("username", "email", "role", "is_staff", "is_active", "mfa_enrolled", "top_enabled", "updated_at")
    list_filter = ("role", "is_staff", "is_active", "mfa_enrolled", "top_enabled")


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ("title", "status", "author", "created_at", "updated_at")
    list_filter = ("status", "created_at")
    search_fields = ("title", "author__username", "context")


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ("title", "report", "kb_entry", "severity_level", "cvss_score", "display_order")
    list_filter = ("severity_level", "cvss_score")
    search_fields = ("title", "report__title", "kb_entry__name")


@admin.register(KnowledgeBase)
class KnowledgeBaseAdmin(admin.ModelAdmin):
    list_display = ("name", "category", "default_severity", "updated_at")
    list_filter = ("category", "default_severity")
    search_fields = ("name", "category")


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("created_at", "actor", "action", "object_type", "object_id", "ip_address")
    list_filter = ("action", "created_at")
    search_fields = ("actor__username", "object_type", "object_id", "ip_address")
    readonly_fields = ("created_at",)


@admin.register(TopDevice)
class TopDeviceAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "secret_key", "is_confirmed", "created_at")
    list_filter = ("is_confirmed", "created_at")
    search_fields = ("user__username", "secret_key")


@admin.register(WebAuthnCredential)
class WebAuthnCredentialAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "credential_id", "sign_count", "created_at")
    list_filter = ("created_at",)
    search_fields = ("user__username", "credential_id")
