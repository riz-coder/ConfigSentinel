import base64
import binascii
import os
from datetime import timedelta
from pathlib import Path
from urllib.parse import unquote, urlparse

from django.core.exceptions import ImproperlyConfigured
from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def env_bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def env_list(name: str, default: str = "") -> list[str]:
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


DEBUG = env_bool("CONFIGSENTINEL_DEBUG", True)
PRODUCT_NAME = os.getenv("CONFIGSENTINEL_PRODUCT_NAME", "Assurance Workspace").strip() or "Assurance Workspace"
SECRET_KEY = os.getenv("CONFIGSENTINEL_SECRET_KEY", "")
if not SECRET_KEY:
    if DEBUG:
        SECRET_KEY = "unsafe-local-development-key"
    else:
        raise ImproperlyConfigured("CONFIGSENTINEL_SECRET_KEY is required when DEBUG=false")

ALLOWED_HOSTS = env_list("CONFIGSENTINEL_ALLOWED_HOSTS", "localhost,127.0.0.1")
if not DEBUG and not ALLOWED_HOSTS:
    raise ImproperlyConfigured("CONFIGSENTINEL_ALLOWED_HOSTS is required when DEBUG=false")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "axes",
    "django_otp",
    "django_otp.plugins.otp_totp",
    "django_otp.plugins.otp_static",
    "rest_framework",
    "apps.security",
    "apps.tenancy",
    "apps.auditlog",
    "apps.regulatory",
    "apps.evidence",
    "apps.inventory",
    "apps.collector",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django_otp.middleware.OTPMiddleware",
    "apps.security.middleware.MFAEnforcementMiddleware",
    "apps.tenancy.middleware.TenantContextMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "axes.middleware.AxesMiddleware",
]

ROOT_URLCONF = "configsentinel.urls"
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "configsentinel.context_processors.product_branding",
            ],
        },
    }
]
WSGI_APPLICATION = "configsentinel.wsgi.application"


def database_config(url: str) -> dict:
    parsed = urlparse(url)
    if parsed.scheme == "sqlite":
        path = unquote(parsed.path.lstrip("/"))
        return {"ENGINE": "django.db.backends.sqlite3", "NAME": BASE_DIR / path}
    if parsed.scheme in {"postgres", "postgresql"}:
        return {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": parsed.path.lstrip("/"),
            "USER": unquote(parsed.username or ""),
            "PASSWORD": unquote(parsed.password or ""),
            "HOST": parsed.hostname or "",
            "PORT": parsed.port or 5432,
            "CONN_MAX_AGE": 60,
            "OPTIONS": {"sslmode": os.getenv("CONFIGSENTINEL_DB_SSLMODE", "prefer")},
        }
    raise ImproperlyConfigured("Unsupported CONFIGSENTINEL_DATABASE_URL scheme")


DATABASES = {
    "default": database_config(os.getenv("CONFIGSENTINEL_DATABASE_URL", "sqlite:///db.sqlite3"))
}
DATABASES["default"]["ATOMIC_REQUESTS"] = True

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]
LANGUAGE_CODE = "en-us"
TIME_ZONE = "Asia/Karachi"
USE_I18N = True
USE_TZ = True
STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
EVIDENCE_STORAGE_ROOT = Path(os.getenv("CONFIGSENTINEL_EVIDENCE_STORAGE_ROOT", BASE_DIR / "evidence_objects"))
EVIDENCE_MASTER_KEY = os.getenv("CONFIGSENTINEL_EVIDENCE_MASTER_KEY", "")
EVIDENCE_MAX_UPLOAD_BYTES = int(os.getenv("CONFIGSENTINEL_EVIDENCE_MAX_UPLOAD_BYTES", str(25 * 1024 * 1024)))
if not DEBUG and not EVIDENCE_MASTER_KEY:
    raise ImproperlyConfigured("CONFIGSENTINEL_EVIDENCE_MASTER_KEY is required when DEBUG=false")
if EVIDENCE_MASTER_KEY:
    try:
        decoded_evidence_key = base64.b64decode(EVIDENCE_MASTER_KEY, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ImproperlyConfigured("CONFIGSENTINEL_EVIDENCE_MASTER_KEY must be valid base64") from exc
    if len(decoded_evidence_key) != 32:
        raise ImproperlyConfigured("CONFIGSENTINEL_EVIDENCE_MASTER_KEY must decode to exactly 32 bytes")
if EVIDENCE_MAX_UPLOAD_BYTES <= 0:
    raise ImproperlyConfigured("CONFIGSENTINEL_EVIDENCE_MAX_UPLOAD_BYTES must be positive")
FILE_UPLOAD_HANDLERS = ["django.core.files.uploadhandler.MemoryFileUploadHandler"]
FILE_UPLOAD_MAX_MEMORY_SIZE = EVIDENCE_MAX_UPLOAD_BYTES + (1024 * 1024)
# Multipart form overhead must not make an otherwise permitted evidence PDF
# fail before the bounded in-memory upload handler receives it.
DATA_UPLOAD_MAX_MEMORY_SIZE = EVIDENCE_MAX_UPLOAD_BYTES + (1024 * 1024)
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "dashboard"
LOGOUT_REDIRECT_URL = "login"
OTP_LOGIN_URL = "mfa-verify"
OTP_TOTP_ISSUER = os.getenv("CONFIGSENTINEL_TOTP_ISSUER", PRODUCT_NAME)

AUTHENTICATION_BACKENDS = [
    "axes.backends.AxesStandaloneBackend",
    "django.contrib.auth.backends.ModelBackend",
]
AXES_FAILURE_LIMIT = 5
AXES_COOLOFF_TIME = timedelta(minutes=30)
AXES_LOCKOUT_PARAMETERS = [["username", "ip_address"]]
AXES_IPWARE_PROXY_COUNT = 1
AXES_RESET_ON_SUCCESS = True
AXES_ENABLE_RETRY_AFTER_HEADER = True
AXES_VERBOSE = False

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["rest_framework.authentication.SessionAuthentication"],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_PAGINATION_CLASS": "configsentinel.pagination.CreatedAtCursorPagination",
    "PAGE_SIZE": 50,
}

CSRF_TRUSTED_ORIGINS = env_list("CONFIGSENTINEL_CSRF_TRUSTED_ORIGINS")
SECURE_SSL_REDIRECT = env_bool("CONFIGSENTINEL_SECURE_SSL_REDIRECT", not DEBUG)
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SECURE_HSTS_SECONDS = 0 if DEBUG else 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = not DEBUG
SECURE_HSTS_PRELOAD = not DEBUG
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

