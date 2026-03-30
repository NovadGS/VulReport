from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin

from .models import (
    AuditLog,
    Finding,
    FindingComment,
    FriendRequest,
    KnowledgeBase,
    Organization,
    OrganizationMembership,
    Report,
    ReportOrganizationShare,
    TopDevice,
    User,
    WebAuthnCredential,
)


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    fieldsets = DjangoUserAdmin.fieldsets + (
        ("Security", {"fields": ("profile_id", "role", "mfa_required", "mfa_enrolled", "top_enabled")}),
    )
    readonly_fields = ("profile_id",)
    list_display = ("username", "profile_id", "email", "role", "is_staff", "is_active", "mfa_enrolled", "top_enabled", "updated_at")
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


@admin.register(FindingComment)
class FindingCommentAdmin(admin.ModelAdmin):
    list_display = ("finding", "author", "created_at", "is_internal")
    list_filter = ("is_internal", "created_at")
    search_fields = ("finding__title", "author__username", "body")


@admin.register(KnowledgeBase)
class KnowledgeBaseAdmin(admin.ModelAdmin):
    list_display = ("name", "category", "default_severity", "updated_at")
    list_filter = ("category", "default_severity")
    search_fields = ("name", "category")


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ("name", "owner", "created_at")
    search_fields = ("name", "owner__username")


@admin.register(OrganizationMembership)
class OrganizationMembershipAdmin(admin.ModelAdmin):
    list_display = ("organization", "user", "role", "created_at")
    list_filter = ("role",)
    search_fields = ("organization__name", "user__username")


@admin.register(ReportOrganizationShare)
class ReportOrganizationShareAdmin(admin.ModelAdmin):
    list_display = ("report", "organization", "created_by", "created_at")
    search_fields = ("report__title", "organization__name", "created_by__username")


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("created_at", "actor", "action", "object_type", "object_id", "ip_address")
    list_filter = ("action", "created_at")
    search_fields = ("actor__username", "object_type", "object_id", "ip_address")
    readonly_fields = ("created_at",)


@admin.register(FriendRequest)
class FriendRequestAdmin(admin.ModelAdmin):
    list_display = ("id", "from_user", "to_user", "status", "created_at", "responded_at")
    list_filter = ("status", "created_at")
    search_fields = ("from_user__username", "to_user__username", "from_user__profile_id", "to_user__profile_id")
    readonly_fields = ("created_at", "responded_at")


@admin.register(TopDevice)
class TopDeviceAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "is_confirmed", "created_at")
    list_filter = ("is_confirmed", "created_at")
    search_fields = ("user__username",)
    readonly_fields = ("created_at",)


@admin.register(WebAuthnCredential)
class WebAuthnCredentialAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "credential_id", "sign_count", "created_at")
    list_filter = ("created_at",)
    search_fields = ("user__username", "credential_id")
