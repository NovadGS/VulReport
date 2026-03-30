from typing import Any

from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.conf import settings
from django.dispatch import receiver
from django.shortcuts import redirect
from django.urls import resolve

from .models import AuditAction, AuditLog
from .models import UserRole


def _extract_ip(meta: dict[str, Any]) -> str | None:
    remote_addr = meta.get("REMOTE_ADDR")
    forwarded = meta.get("HTTP_X_FORWARDED_FOR")
    if forwarded and remote_addr and remote_addr in settings.TRUSTED_PROXY_IPS:
        return forwarded.split(",")[0].strip()
    return remote_addr


class AuditLogMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.client_ip = _extract_ip(request.META)
        return self.get_response(request)


class MFAGuardMiddleware:
    """
    Enforce role-based MFA after authentication.

    - Viewer: no MFA.
    - Pentester: mandatory TOTP (enroll + verify each session).
    - Admin: mandatory TOTP (enroll + verify each session).
    """

    ALLOW_URL_NAMES = {
        "login",
        "logout",
        "register",
        "activate_account",
        "mfa_setup",
        "mfa_verify",
        "admin:login",
    }

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            try:
                url_name = resolve(request.path_info).url_name
            except Exception:
                url_name = None

            if url_name not in self.ALLOW_URL_NAMES:
                if request.user.role in {UserRole.PENTESTER, UserRole.ADMIN}:
                    if not request.user.mfa_enrolled:
                        request.session["post_mfa_redirect"] = request.get_full_path()
                        return redirect("mfa_setup")
                    if not request.session.get("mfa_ok"):
                        request.session["post_mfa_redirect"] = request.get_full_path()
                        return redirect("mfa_verify")

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
