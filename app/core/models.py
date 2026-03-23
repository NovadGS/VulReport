from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models


class UserRole(models.TextChoices):
    ADMIN = "admin", "Admin"
    PENTESTER = "pentester", "Pentester"
    VIEWER = "viewer", "Viewer"


class User(AbstractUser):
    role = models.CharField(max_length=20, choices=UserRole.choices, default=UserRole.VIEWER, db_index=True)
    mfa_required = models.BooleanField(default=False)
    mfa_enrolled = models.BooleanField(default=False)

    def __str__(self) -> str:
        return f"{self.username} ({self.role})"


class ReportStatus(models.TextChoices):
    DRAFT = "draft", "Brouillon"
    IN_REVIEW = "in_review", "En revue"
    FINAL = "final", "Final"
    ARCHIVED = "archived", "Archive"


class Report(models.Model):
    title = models.CharField(max_length=255)
    client = models.CharField(max_length=255, db_index=True)
    report_date = models.DateField()
    status = models.CharField(max_length=20, choices=ReportStatus.choices, default=ReportStatus.DRAFT, db_index=True)
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="reports")
    viewers = models.ManyToManyField(settings.AUTH_USER_MODEL, blank=True, related_name="assigned_reports")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-report_date", "-created_at")

    def __str__(self) -> str:
        return f"{self.title} - {self.client}"


class AuditAction(models.TextChoices):
    LOGIN = "login", "Connexion"
    LOGOUT = "logout", "Deconnexion"
    CREATE = "create", "Creation"
    UPDATE = "update", "Modification"
    DELETE = "delete", "Suppression"
    PRIVILEGE_CHANGE = "privilege_change", "Changement de privileges"


class AuditLog(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="audit_logs",
    )
    action = models.CharField(max_length=50, choices=AuditAction.choices, db_index=True)
    object_type = models.CharField(max_length=100, blank=True)
    object_id = models.CharField(max_length=50, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    details = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ("-timestamp",)

    def __str__(self) -> str:
        username = self.user.username if self.user else "anonymous"
        return f"{self.timestamp.isoformat()} - {username} - {self.action}"


class Finding(models.Model):
    report = models.ForeignKey(Report, on_delete=models.CASCADE, related_name="findings")
    title = models.CharField(max_length=255)
    description = models.TextField()
    evidence_text = models.TextField(blank=True)
    evidence_image = models.ImageField(upload_to="evidence/", null=True, blank=True)
    cvss_score = models.DecimalField(
        max_digits=4,
        decimal_places=1,
        validators=[MinValueValidator(0.0), MaxValueValidator(10.0)],
    )
    remediation = models.TextField()
    owasp_category = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return self.title


class KnowledgeBase(models.Model):
    title = models.CharField(max_length=255)
    cwe = models.CharField(max_length=50, db_index=True)
    description = models.TextField()
    recommendation = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Knowledge base entry"
        verbose_name_plural = "Knowledge base entries"
        ordering = ("title",)

    def __str__(self) -> str:
        return f"{self.title} ({self.cwe})"
