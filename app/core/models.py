import uuid

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils import timezone


class UserRole(models.TextChoices):
    ADMIN = "admin", "Admin"
    PENTESTER = "pentester", "Pentester"
    VIEWER = "viewer", "Viewer"


class User(AbstractUser):
    # Colonnes alignées sur le diagramme (schema cible) :
    # - password_hash au lieu de password (db_column uniquement)
    # - created_at / updated_at
    password = models.CharField(max_length=128, db_column="password_hash", verbose_name="password")
    date_joined = models.DateTimeField(
        default=timezone.now, verbose_name="date joined", db_column="created_at"
    )
    updated_at = models.DateTimeField(auto_now=True, db_column="updated_at")

    profile_id = models.CharField(max_length=16, unique=True, blank=True, editable=False)
    role = models.CharField(max_length=20, choices=UserRole.choices, default=UserRole.VIEWER, db_index=True)
    company_name = models.CharField(max_length=255, blank=True, default="")
    profile_photo = models.ImageField(upload_to="profiles/", blank=True, null=True)
    company_logo = models.ImageField(upload_to="companies/", blank=True, null=True)
    mfa_required = models.BooleanField(default=False, db_column="mfa_required")
    mfa_enrolled = models.BooleanField(default=False, db_column="is_mfa_verified")
    top_enabled = models.BooleanField(default=False, db_column="top_enabled")

    class Meta:
        db_table = "users"
        verbose_name = "user"
        verbose_name_plural = "users"

    @staticmethod
    def generate_profile_id() -> str:
        return f"VR-{uuid.uuid4().hex[:8].upper()}"

    def save(self, *args, **kwargs):
        if not self.profile_id:
            manager = type(self).objects
            while True:
                candidate = self.generate_profile_id()
                if not manager.filter(profile_id=candidate).exclude(pk=self.pk).exists():
                    self.profile_id = candidate
                    break
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f"{self.username} ({self.role})"


class ReportStatus(models.TextChoices):
    DRAFT = "draft", "Brouillon"
    IN_REVIEW = "in_review", "En revue"
    FINAL = "final", "Final"
    ARCHIVED = "archived", "Archive"


class SeverityLevel(models.IntegerChoices):
    LOW = 1, "Low"
    MEDIUM = 2, "Medium"
    HIGH = 3, "High"
    CRITICAL = 4, "Critical"


class KBCategory(models.TextChoices):
    WEB = "web", "Web"
    CRYPTO = "crypto", "Crypto"
    NETWORK = "network", "Network"
    INJECTION = "injection", "Injection"
    AUTH = "auth", "Broken Authentication"
    XSS = "xss", "Cross-Site Scripting"
    ACCESS_CONTROL = "access_control", "Broken Access Control"
    MISCONFIG = "misconfig", "Security Misconfiguration"
    COMPONENTS = "components", "Vulnerable Components"
    LOGGING = "logging", "Logging & Monitoring"


class Report(models.Model):
    title = models.CharField(max_length=255)
    context = models.TextField()
    executive_summary = models.TextField(blank=True, default="")
    company_name = models.CharField(max_length=255, blank=True, default="")
    company_logo_url = models.URLField(blank=True, default="")
    custom_header = models.CharField(max_length=255, blank=True, default="")
    public_share_token = models.CharField(max_length=64, blank=True, default="", db_index=True)
    public_share_expires_at = models.DateTimeField(null=True, blank=True)
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="approved_reports",
    )
    approved_at = models.DateTimeField(null=True, blank=True)
    confidentiality_mark = models.CharField(max_length=30, blank=True, default="CONFIDENTIEL")
    is_public = models.BooleanField(default=False, db_index=True)
    status = models.CharField(
        max_length=20, choices=ReportStatus.choices, default=ReportStatus.DRAFT, db_index=True
    )
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="reports")
    viewers = models.ManyToManyField(settings.AUTH_USER_MODEL, blank=True, through="ReportViewer", related_name="assigned_reports")
    organizations = models.ManyToManyField(
        "Organization",
        blank=True,
        through="ReportOrganizationShare",
        related_name="shared_reports",
    )
    created_at = models.DateTimeField(auto_now_add=True, db_column="created_at")
    updated_at = models.DateTimeField(auto_now=True, db_column="updated_at")

    class Meta:
        db_table = "reports"
        ordering = ("-created_at",)

    def __str__(self) -> str:
        return f"{self.title}"


class ReportViewer(models.Model):
    report = models.ForeignKey(Report, on_delete=models.CASCADE)
    viewer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    assigned_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "report_viewers"
        unique_together = ("report", "viewer")
        ordering = ("-assigned_at",)


class AuditAction(models.TextChoices):
    LOGIN = "login", "Connexion"
    LOGOUT = "logout", "Deconnexion"
    CREATE = "create", "Creation"
    UPDATE = "update", "Modification"
    DELETE = "delete", "Suppression"
    PRIVILEGE_CHANGE = "privilege_change", "Changement de privileges"


class AuditLog(models.Model):
    # diagramme: audit_logs.actor_id / metadata / created_at
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="audit_logs",
    )
    action = models.CharField(max_length=50, choices=AuditAction.choices, db_index=True)
    object_type = models.CharField(max_length=50, blank=True)
    object_id = models.IntegerField(null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = "audit_logs"
        ordering = ("-created_at",)

    def __str__(self) -> str:
        username = self.actor.username if self.actor else "anonymous"
        return f"{self.created_at.isoformat()} - {username} - {self.action}"


class TopDevice(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="top_devices")
    secret_key = models.CharField(max_length=255, db_index=True)
    is_confirmed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "top_devices"
        ordering = ("-created_at",)


class WebAuthnCredential(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="webauthn_credentials")
    credential_id = models.CharField(max_length=512, unique=True, db_index=True)
    public_key = models.CharField(max_length=512)
    sign_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "webauthn_credentials"
        ordering = ("-created_at",)


class Finding(models.Model):
    report = models.ForeignKey(Report, on_delete=models.CASCADE, related_name="findings")
    kb_entry = models.ForeignKey("KnowledgeBase", on_delete=models.SET_NULL, null=True, blank=True, related_name="findings")
    cve_id = models.CharField(max_length=20, blank=True, default="", db_index=True)
    source_urls = models.JSONField(default=list, blank=True)
    title = models.CharField(max_length=255)
    description = models.TextField()
    proof_poc = models.TextField(blank=True, default="")
    impact = models.TextField(blank=True, default="")
    recommendation = models.TextField(blank=True, default="")
    references = models.TextField(blank=True, default="")
    severity_level = models.IntegerField(
        choices=SeverityLevel.choices,
        default=SeverityLevel.LOW,
        db_index=True,
    )
    cvss_score = models.DecimalField(
        max_digits=3,
        decimal_places=1,
        validators=[MinValueValidator(0.0), MaxValueValidator(10.0)],
    )
    display_order = models.IntegerField(default=0, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "findings"
        ordering = ("display_order", "-created_at")

    def __str__(self) -> str:
        return self.title


class FindingComment(models.Model):
    finding = models.ForeignKey(Finding, on_delete=models.CASCADE, related_name="comments")
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="finding_comments")
    body = models.TextField()
    is_internal = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "finding_comments"
        ordering = ("created_at",)


class OrganizationRole(models.TextChoices):
    OWNER = "owner", "Owner"
    ADMIN = "admin", "Admin"
    MEMBER = "member", "Member"


class Organization(models.Model):
    name = models.CharField(max_length=255, unique=True)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="owned_organizations")
    created_at = models.DateTimeField(auto_now_add=True)
    members = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        through="OrganizationMembership",
        related_name="organizations",
    )

    class Meta:
        db_table = "organizations"
        ordering = ("name",)

    def __str__(self) -> str:
        return self.name


class OrganizationMembership(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="memberships")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="organization_memberships")
    role = models.CharField(max_length=20, choices=OrganizationRole.choices, default=OrganizationRole.MEMBER)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "organization_memberships"
        unique_together = ("organization", "user")


class FriendRequestStatus(models.TextChoices):
    PENDING = "pending", "En attente"
    ACCEPTED = "accepted", "Acceptee"
    DECLINED = "declined", "Refusee"


class FriendRequest(models.Model):
    from_user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="sent_friend_requests")
    to_user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="received_friend_requests")
    status = models.CharField(max_length=20, choices=FriendRequestStatus.choices, default=FriendRequestStatus.PENDING, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    responded_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "friend_requests"
        ordering = ("-created_at",)
        constraints = [
            models.UniqueConstraint(fields=("from_user", "to_user"), name="unique_friend_request_direction"),
            models.CheckConstraint(check=~models.Q(from_user=models.F("to_user")), name="prevent_self_friend_request"),
        ]

    def __str__(self) -> str:
        return f"{self.from_user.username} -> {self.to_user.username} ({self.status})"


class ReportOrganizationShare(models.Model):
    report = models.ForeignKey(Report, on_delete=models.CASCADE, related_name="organization_shares")
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="report_shares")
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "report_organization_shares"
        unique_together = ("report", "organization")


class KnowledgeBase(models.Model):
    name = models.CharField(max_length=255, db_index=True)
    description = models.TextField()
    recommendation = models.TextField()
    references = models.TextField(blank=True, default="")
    default_severity = models.IntegerField(
        choices=SeverityLevel.choices,
        default=SeverityLevel.LOW,
    )
    category = models.CharField(max_length=50, choices=KBCategory.choices, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "kb_entries"
        verbose_name = "Knowledge base entry"
        verbose_name_plural = "Knowledge base entries"
        ordering = ("name",)

    def __str__(self) -> str:
        return f"{self.name} ({self.category})"
