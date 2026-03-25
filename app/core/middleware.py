from typing import Any

from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver

from .models import AuditAction, AuditLog


def _extract_ip(meta: dict[str, Any]) -> str | None:
    forwarded = meta.get("HTTP_X_FORWARDED_FOR")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return meta.get("REMOTE_ADDR")


class AuditLogMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.client_ip = _extract_ip(request.META)
        return self.get_response(request)


@receiver(user_logged_in)
def log_user_logged_in(sender, request, user, **kwargs):
    AuditLog.objects.create(
        actor=user,
        action=AuditAction.LOGIN,
        ip_address=getattr(request, "client_ip", _extract_ip(request.META)),
        metadata={"source": "django_auth"},
    )


@receiver(user_logged_out)
def log_user_logged_out(sender, request, user, **kwargs):
    AuditLog.objects.create(
        actor=user,
        action=AuditAction.LOGOUT,
        ip_address=getattr(request, "client_ip", _extract_ip(request.META)) if request else None,
        metadata={"source": "django_auth"},
    )
