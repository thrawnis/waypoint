from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import redirect
from django.urls import reverse


class HtmxRedirectMiddleware:
    """Convert server redirects on HTMX requests into HX-Redirect responses.

    Without this, a gate redirect (terms re-acceptance, expired session, 2FA)
    fired during an HTMX action would swap the *full* target page into a small
    partial container, mangling the layout. HX-Redirect makes the browser do a
    proper full-page navigation instead."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if (
            request.headers.get("HX-Request") == "true"
            and response.status_code in (301, 302, 303, 307, 308)
        ):
            hx = HttpResponse(status=204)
            hx["HX-Redirect"] = response["Location"]
            return hx
        return response


# URL names that every gate must leave reachable, so one gate never blocks
# another gate's remediation page (order of middlewares then just decides which
# gate a user is sent to first).
_GATE_EXEMPT_NAMES = (
    "logout",
    "verify_email", "verify_email_resend", "verify_email_confirm", "register_confirm",
    "two_factor_setup", "two_factor_setup_totp", "two_factor_setup_passkey",
    "two_factor_verify", "two_factor_disable", "two_factor_settings",
    "passkey_register_options", "passkey_register_verify", "passkey_delete",
    "terms", "terms_accept", "terms_decline",
)


def _is_gate_exempt(request):
    path = request.path
    for name in _GATE_EXEMPT_NAMES:
        try:
            if path == reverse(name):
                return True
        except Exception:
            pass
    return (
        path.startswith(settings.STATIC_URL)
        or path.startswith(getattr(settings, "MEDIA_URL", "/media/"))
    )


class EmailVerificationMiddleware:
    """Require every authenticated user to confirm their email before using the
    app. Disabled when settings.REQUIRE_EMAIL_VERIFICATION is False."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if getattr(settings, "REQUIRE_EMAIL_VERIFICATION", True):
            user = getattr(request, "user", None)
            if user is not None and user.is_authenticated:
                if not request.session.get("email_verified") and not _is_gate_exempt(request):
                    from .models import EmailVerification
                    ev = EmailVerification.objects.filter(user=user).first()
                    if ev and ev.verified:
                        request.session["email_verified"] = True
                    else:
                        return redirect("verify_email")
        return self.get_response(request)


class TwoFactorMiddleware:
    """Admins must have two-factor authentication enabled — a passkey (the
    default/primary method) or a confirmed TOTP device (the secondary one);
    either alone is enough. Any signed-in admin with neither is redirected
    to the setup page until they finish. Optional (unenforced) for non-admin
    users."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, "user", None)
        if user is not None and user.is_authenticated and user.is_staff:
            if not request.session.get("twofa_ok") and not _is_gate_exempt(request):
                from .permissions import user_has_mfa
                if user_has_mfa(user):
                    request.session["twofa_ok"] = True
                else:
                    return redirect("two_factor_setup")
        return self.get_response(request)


class TermsAcceptanceMiddleware:
    """Require every authenticated user to accept the current Terms of Service.
    Bumping TERMS_VERSION forces everyone to re-accept."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, "user", None)
        if user is not None and user.is_authenticated:
            current = settings.TERMS_VERSION
            if request.session.get("tos_accepted_version") != current and not _is_gate_exempt(request):
                from .models import TermsAcceptance
                if TermsAcceptance.objects.filter(user=user, version=current).exists():
                    request.session["tos_accepted_version"] = current
                else:
                    return redirect("{}?next={}".format(reverse("terms"), request.path))
        return self.get_response(request)
