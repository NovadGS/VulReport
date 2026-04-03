import os
from pathlib import Path
from django.core.exceptions import ImproperlyConfigured
from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")
load_dotenv(BASE_DIR.parent / ".env")


def _env_str(*names: str, default: str = "") -> str:
    for name in names:
        value = os.getenv(name)
        if value is not None and value.strip() != "":
            return value.strip()
    return default


def _env_bool(*names: str, default: bool = False) -> bool:
    for name in names:
        value = os.getenv(name)
        if value is not None and value.strip() != "":
            return value.strip().lower() in {"1", "true", "yes", "on"}
    return default


SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "").strip() or os.getenv("SECRET_KEY", "").strip()
if not SECRET_KEY:
    raise ImproperlyConfigured("DJANGO_SECRET_KEY must be set.")
DEBUG = os.getenv("DJANGO_DEBUG", "False").lower() == "true"

ALLOWED_HOSTS = [host.strip() for host in os.getenv("DJANGO_ALLOWED_HOSTS", "localhost").split(",") if host.strip()]
CSRF_TRUSTED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("DJANGO_CSRF_TRUSTED_ORIGINS", "http://localhost").split(",")
    if origin.strip()
]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "csp",
    "axes",
    "core",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "axes.middleware.AxesMiddleware",
    "core.middleware.AuditLogMiddleware",
    "core.middleware.MFAGuardMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("POSTGRES_DB", "vulnreport"),
        "USER": os.getenv("POSTGRES_USER", "vulnreport"),
        "PASSWORD": os.getenv("POSTGRES_PASSWORD", "vulnreport"),
        "HOST": os.getenv("POSTGRES_HOST", "db"),
        "PORT": os.getenv("POSTGRES_PORT", "5432"),
        "CONN_MAX_AGE": 60,
        "OPTIONS": {"sslmode": "prefer"},
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 10}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
]

AUTHENTICATION_BACKENDS = [
    "axes.backends.AxesStandaloneBackend",
    "django.contrib.auth.backends.ModelBackend",
]

LANGUAGE_CODE = "fr-fr"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
AUTH_USER_MODEL = "core.User"

LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "home"
LOGOUT_REDIRECT_URL = "login"

# Email configuration for account activation
# Alias supportés: EMAIL_*, SMTP_* et MAIL_* pour simplifier le .env.
EMAIL_HOST = _env_str("EMAIL_HOST", "SMTP_HOST", "MAIL_HOST", default="smtp.gmail.com")
EMAIL_PORT = int(_env_str("EMAIL_PORT", "SMTP_PORT", "MAIL_PORT", default="587"))
EMAIL_HOST_USER = _env_str("EMAIL_HOST_USER", "SMTP_USER", "SMTP_USERNAME", "MAIL_USERNAME")
EMAIL_HOST_PASSWORD = _env_str("EMAIL_HOST_PASSWORD", "SMTP_PASSWORD", "SMTP_PASS", "MAIL_PASSWORD")
EMAIL_USE_SSL = _env_bool("EMAIL_USE_SSL", "SMTP_USE_SSL", "MAIL_USE_SSL", default=EMAIL_PORT == 465)
EMAIL_USE_TLS = _env_bool("EMAIL_USE_TLS", "SMTP_USE_TLS", "MAIL_USE_TLS", default=not EMAIL_USE_SSL)
if EMAIL_USE_SSL:
    EMAIL_USE_TLS = False
DEFAULT_FROM_EMAIL = _env_str(
    "DEFAULT_FROM_EMAIL",
    "EMAIL_FROM",
    "SMTP_FROM_EMAIL",
    default=EMAIL_HOST_USER or "noreply@vulnreport.local",
)
SERVER_EMAIL = DEFAULT_FROM_EMAIL
EMAIL_TIMEOUT = int(_env_str("EMAIL_TIMEOUT", "SMTP_TIMEOUT", default="20"))

_email_backend = _env_str("EMAIL_BACKEND", default="")
if _email_backend:
    EMAIL_BACKEND = _email_backend
else:
    EMAIL_BACKEND = (
        "django.core.mail.backends.smtp.EmailBackend"
        if (EMAIL_HOST_USER and EMAIL_HOST_PASSWORD)
        else "django.core.mail.backends.console.EmailBackend"
    )

# Security headers and cookie hardening
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SECURE_REFERRER_POLICY = "same-origin"
SECURE_SSL_REDIRECT = os.getenv("SECURE_SSL_REDIRECT", "True" if not DEBUG else "False").lower() == "true"
SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "True" if not DEBUG else "False").lower() == "true"
CSRF_COOKIE_SECURE = os.getenv("CSRF_COOKIE_SECURE", "True" if not DEBUG else "False").lower() == "true"
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"
SECURE_HSTS_SECONDS = int(os.getenv("SECURE_HSTS_SECONDS", "31536000" if not DEBUG else "0"))
SECURE_HSTS_INCLUDE_SUBDOMAINS = os.getenv("SECURE_HSTS_INCLUDE_SUBDOMAINS", "True").lower() == "true"
SECURE_HSTS_PRELOAD = os.getenv("SECURE_HSTS_PRELOAD", "True").lower() == "true"
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# Operational security flags
ENABLE_MFA_ADMIN_SIMULATION = os.getenv("ENABLE_MFA_ADMIN_SIMULATION", "False").lower() == "true"
MFA_TOTP_ENCRYPTION_KEY = os.getenv("MFA_TOTP_ENCRYPTION_KEY", "").strip()
MAX_IMPORT_FILE_SIZE = int(os.getenv("MAX_IMPORT_FILE_SIZE", str(2 * 1024 * 1024)))
MAX_IMPORT_FINDINGS = int(os.getenv("MAX_IMPORT_FINDINGS", "200"))
TRUSTED_PROXY_IPS = tuple(
    item.strip() for item in os.getenv("TRUSTED_PROXY_IPS", "").split(",") if item.strip()
)

# VirusTotal integration (optional)
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
VIRUSTOTAL_ENABLED = bool(VIRUSTOTAL_API_KEY)

# Brute-force protection (django-axes)
AXES_ENABLED = True
AXES_FAILURE_LIMIT = int(os.getenv("AXES_FAILURE_LIMIT", "5"))
AXES_COOLOFF_TIME = float(os.getenv("AXES_COOLOFF_TIME_HOURS", "1"))
AXES_LOCKOUT_CALLABLE = None
AXES_LOCK_OUT_AT_FAILURE = True
AXES_RESET_ON_SUCCESS = True

# Django CSP strict baseline
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)
CSP_STYLE_SRC = ("'self'", "https://cdn.jsdelivr.net")
CSP_IMG_SRC = ("'self'", "data:")
CSP_FONT_SRC = ("'self'", "https://cdn.jsdelivr.net")
CSP_CONNECT_SRC = ("'self'",)
CSP_OBJECT_SRC = ("'none'",)
CSP_BASE_URI = ("'self'",)
CSP_FRAME_ANCESTORS = ("'none'",)

# WebAuthn/MFA preparation hooks (django-mfa2)
MFA_UNALLOWED_METHODS = ("Email",)
