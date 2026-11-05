import os
from pathlib import Path

import dj_database_url

BASE_DIR = Path(__file__).resolve().parent.parent

_DEFAULT_SECRET_KEY = "dev-insecure-key-change-in-production"
SECRET_KEY = os.environ.get("SECRET_KEY", _DEFAULT_SECRET_KEY)
DEBUG = os.environ.get("DEBUG", "False").lower() == "true"

# Refuse to run in production on the public default key — it signs session
# cookies AND email-verification tokens, so a known key is forgeable.
if not DEBUG and SECRET_KEY == _DEFAULT_SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY is unset — set the SECRET_KEY environment variable "
        "(the built-in default is public and insecure) or run with DEBUG=True."
    )

ALLOWED_HOSTS = [h.strip() for h in os.environ.get("ALLOWED_HOSTS", "*").split(",")]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "whitenoise.runserver_nostatic",
    "django.contrib.staticfiles",
    "tracker",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "tracker.middleware.HtmxRedirectMiddleware",
    "tracker.middleware.EmailVerificationMiddleware",
    "tracker.middleware.TwoFactorMiddleware",
    "tracker.middleware.TermsAcceptanceMiddleware",
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
                "tracker.context_processors.app_version",
                "tracker.context_processors.onbehalf_pending",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

DATABASES = {
    "default": dj_database_url.config(
        default=f"sqlite:///{BASE_DIR / 'data' / 'db.sqlite3'}",
        conn_max_age=600,
    )
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "data" / "staticfiles"
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "data" / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

APP_VERSION = os.environ.get("GIT_COMMIT", "dev")

GOOGLE_MAPS_API_KEY = os.environ.get("GOOGLE_MAPS_API_KEY", "")

# Terms of Service. Bump this version whenever the terms text changes
# (tracker/templates/legal/terms.html) to force every user to re-accept.
TERMS_VERSION = os.environ.get("TERMS_VERSION", "2026-01-05")

# ── Email / verification ───────────────────────────────────────────────────────
# Require users to confirm their email before using the app. Set to False to
# disable (e.g. if no mail server is available).
REQUIRE_EMAIL_VERIFICATION = os.environ.get("REQUIRE_EMAIL_VERIFICATION", "True").lower() == "true"
# Default to the console backend (prints emails to the container logs) so the
# app works out of the box; set EMAIL_HOST etc. in .env to send real mail.
EMAIL_BACKEND = os.environ.get(
    "EMAIL_BACKEND", "django.core.mail.backends.console.EmailBackend"
)
EMAIL_HOST = os.environ.get("EMAIL_HOST", "")
EMAIL_PORT = int(os.environ.get("EMAIL_PORT", "587"))
EMAIL_HOST_USER = os.environ.get("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_HOST_PASSWORD", "")
EMAIL_USE_TLS = os.environ.get("EMAIL_USE_TLS", "True").lower() == "true"
DEFAULT_FROM_EMAIL = os.environ.get("DEFAULT_FROM_EMAIL", "Waypoint <no-reply@waypoint.local>")

# ── Google Cloud usage/cost reporting (admin "Maps usage" page) ────────────────
# Optional. When set, the admin page pulls real call counts (Cloud Monitoring)
# and cost (BigQuery billing export) for the current billing month.
GCP_PROJECT_ID = os.environ.get("GCP_PROJECT_ID", "")
# Path to a service-account JSON key mounted into the container (read-only).
GCP_CREDENTIALS_FILE = os.environ.get("GCP_CREDENTIALS_FILE", "")
# Fully-qualified billing-export table, e.g.
#   my-project.billing_export.gcp_billing_export_v1_XXXXXX_XXXXXX_XXXXXX
GCP_BILLING_BQ_TABLE = os.environ.get("GCP_BILLING_BQ_TABLE", "")

LOGIN_URL = "/accounts/login/"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/"

# Usernames are treated case-insensitively at login ("Alice" == "alice").
AUTHENTICATION_BACKENDS = [
    "tracker.auth_backends.CaseInsensitiveModelBackend",
]

MESSAGE_STORAGE = "django.contrib.messages.storage.session.SessionStorage"

# ── Cache ──────────────────────────────────────────────────────────────────────
# Rate-limit and 2FA/login throttle counters live in the cache. Set REDIS_URL in
# production (e.g. redis://127.0.0.1:6379/0) so counters are SHARED across all
# gunicorn workers — the LocMemCache fallback is per-process, so throttles are
# only approximate (each worker counts separately) without it.
_redis_url = os.environ.get("REDIS_URL", "").strip()
if _redis_url:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": _redis_url,
        }
    }
else:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "waypoint-default",
        }
    }

# The single request header our trusted edge proxy sets with the real client IP.
# Default suits Cloudflare Tunnel; set CLIENT_IP_HEADER=REMOTE_ADDR when there is
# no trusted proxy. We never trust X-Forwarded-For (a client can spoof it), so
# IP-keyed throttles can't be evaded by forging a header. See tracker.ratelimit.
CLIENT_IP_HEADER = os.environ.get("CLIENT_IP_HEADER", "HTTP_CF_CONNECTING_IP")

# ── Security headers ───────────────────────────────────────────────────────────
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"

# ── Cookie hardening ───────────────────────────────────────────────────────────
SESSION_COOKIE_HTTPONLY = True   # prevent JS from reading the session cookie
SESSION_COOKIE_SAMESITE = "Lax"
# CSRF_COOKIE_HTTPONLY is intentionally left False (Django default) so that
# HTMX can read the csrftoken cookie to attach X-CSRFToken to AJAX requests.
CSRF_COOKIE_SAMESITE = "Lax"

_trusted_origins = os.environ.get("CSRF_TRUSTED_ORIGINS", "").strip()
if _trusted_origins:
    CSRF_TRUSTED_ORIGINS = [o.strip() for o in _trusted_origins.split(",") if o.strip()]

# ── HTTPS mode (set HTTPS_ENABLED=true in .env when behind a TLS proxy) ───────
HTTPS_ENABLED = os.environ.get("HTTPS_ENABLED", "False").lower() == "true"
if HTTPS_ENABLED:
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    SECURE_SSL_REDIRECT = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_HSTS_SECONDS = 31_536_000        # 1 year
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
