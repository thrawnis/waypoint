import json
import logging
import math
import re
import urllib.request
import urllib.parse
from decimal import Decimal, ROUND_HALF_UP
from datetime import timedelta

from django.conf import settings
from django.core import signing
from django.core.mail import send_mail
from django.utils import timezone

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.cache import cache
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import Group, User
from django.db.models import Avg, Count, Exists, Max, OuterRef, Q
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseForbidden, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST

from .forms import (
    CollectionEditForm, CollectionForm, ItemForm, ItemReviewForm, LocationForm,
    LocationReviewForm, PhotoForm, RegisterForm, TakeoutImportForm,
)

from .models import (
    AuditLog, ChainGroup, Collection, Connection, ConnectToken, EmailVerification,
    FriendGroup, FriendGroupJoinRequest,
    FriendGroupMembership, GlutenFreeVote, Item, ItemReview,
    Location, LocationReview, OsmSearchCache, PendingRegistration, Photo,
    TermsAcceptance, TOTPDevice, WebAuthnCredential,
)
from .permissions import SUPERUSER_GROUP_NAME, can_edit_location, is_admin, is_superuser_role, user_has_mfa
from .ratelimit import get_client_ip, ratelimit

logger = logging.getLogger(__name__)


# ── Roles ─────────────────────────────────────────────────────────────────────
# is_admin / is_superuser_role live in tracker/permissions.py (shared with
# templates via the is_superuser_role filter). is_admin gates Django/site-
# infrastructure access; is_superuser_role gates content editing/deleting and
# is a strict superset-safe check (admins pass it too).

def can_delete(user, owner):
    """Destructive actions are allowed for superusers/admins and the original creator."""
    return is_superuser_role(user) or (owner is not None and owner == user)


# ── Audit helpers ─────────────────────────────────────────────────────────────

def _get_ip(request):
    # Single source of truth: the trusted-proxy-aware resolver in ratelimit,
    # which (unlike the old code) never trusts the spoofable X-Forwarded-For.
    return get_client_ip(request)


def _log(request, action, obj, detail=""):
    AuditLog.objects.create(
        user=request.user if request.user.is_authenticated else None,
        action=action,
        model_name=type(obj).__name__,
        object_id=obj.pk,
        object_repr=str(obj)[:255],
        detail=detail,
        ip_address=_get_ip(request),
    )


def _require_reason(request):
    """Deletes must include a non-empty 'reason', recorded in the audit log
    (the UI always supplies one via a prompt/textarea). Returns the trimmed
    reason, or None if missing/blank."""
    reason = (request.POST.get("reason") or "").strip()
    return reason or None


def _location_diff(old, new_data):
    field_labels = {
        "name": "Name",
        "address": "Address",
        "city": "City",
        "state": "State",
        "latitude": "Latitude",
        "longitude": "Longitude",
        "gluten_free": "Gluten-free",
        "dietary_notes": "Dietary notes",
        "public_notes": "Public notes",
        "private_notes": "Private notes",
    }
    parts = []
    for field, label in field_labels.items():
        old_val = str(getattr(old, field) or "")
        new_val = str(new_data.get(field) or "")
        if old_val != new_val:
            parts.append('{}: "{}" -> "{}"'.format(label, old_val, new_val))
    return "; ".join(parts) if parts else "No changes detected"


# ── Auth ──────────────────────────────────────────────────────────────────────

def _safe_next(value):
    # url_has_allowed_host_and_scheme also rejects the backslash/`/\evil.com`
    # trick that a naive startswith("//") check misses.
    from django.utils.http import url_has_allowed_host_and_scheme
    if value and url_has_allowed_host_and_scheme(value, allowed_hosts=None):
        return value
    return ""


# Brute-force throttle for password login (mirrors the 2FA throttle). Keyed on
# username + client IP so one attacker can't lock out a victim globally, while
# still slowing credential-stuffing. Uses the cache backend (see the CACHES
# note in settings for multi-worker deployments).
_LOGIN_MAX_ATTEMPTS = 8
_LOGIN_WINDOW_SECONDS = 300   # 5 minutes


def _login_throttle_key(username, ip):
    return "login_fail_{}_{}".format((username or "").lower()[:150], ip or "")


def _login_throttled(username, ip):
    return cache.get(_login_throttle_key(username, ip), 0) >= _LOGIN_MAX_ATTEMPTS


def _login_record_failure(username, ip):
    key = _login_throttle_key(username, ip)
    try:
        cache.incr(key)
    except ValueError:
        cache.add(key, 1, _LOGIN_WINDOW_SECONDS)


def _login_clear(username, ip):
    cache.delete(_login_throttle_key(username, ip))


def login_view(request):
    if request.user.is_authenticated:
        return redirect("location_list")
    form = AuthenticationForm(request, data=request.POST or None)
    nxt = _safe_next(request.POST.get("next") or request.GET.get("next") or "")
    if request.method == "POST":
        username = request.POST.get("username", "")
        ip = _get_ip(request)
        if _login_throttled(username, ip):
            messages.error(request, "Too many failed attempts. Please wait a few minutes and try again.")
            return render(request, "registration/login.html", {"form": form, "next": nxt})
        if form.is_valid():
            _login_clear(username, ip)
            user = form.get_user()
            if user_has_mfa(user):
                # Password OK, but 2FA is enabled — require a passkey or
                # authenticator code before login.
                request.session["pre_2fa_user"] = user.pk
                request.session["pre_2fa_next"] = nxt
                return redirect("two_factor_verify")
            # No 2FA yet. Admins get forced into setup by the TwoFactorMiddleware.
            login(request, user)
            return redirect(nxt or "location_list")
        # Invalid credentials — count it toward the throttle.
        _login_record_failure(username, ip)
    return render(request, "registration/login.html", {"form": form, "next": nxt})


def logout_view(request):
    logout(request)
    return redirect("location_list")


# ── Two-factor authentication (passkey default, TOTP backup) ──────────────────

def _totp_qr_data_uri(secret, user):
    import io, base64, pyotp, qrcode
    uri = pyotp.TOTP(secret).provisioning_uri(
        name=user.email or user.username, issuer_name="Waypoint"
    )
    buf = io.BytesIO()
    qrcode.make(uri).save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def _totp_valid(secret, code):
    import pyotp
    try:
        return pyotp.TOTP(secret).verify((code or "").strip().replace(" ", ""), valid_window=1)
    except Exception:
        return False


_2FA_MAX_ATTEMPTS = 6          # per window
_2FA_WINDOW_SECONDS = 300      # 5 minutes


def _twofa_throttled(user_pk):
    """True if this user has burned too many wrong codes/passkey attempts recently."""
    return cache.get(f"twofa_fail_{user_pk}", 0) >= _2FA_MAX_ATTEMPTS


def _twofa_record_failure(user_pk):
    key = f"twofa_fail_{user_pk}"
    try:
        cache.add(key, 0, _2FA_WINDOW_SECONDS)
        cache.incr(key)
    except ValueError:
        cache.set(key, 1, _2FA_WINDOW_SECONDS)


def _setup_target_user(request):
    """(user, pending) for whoever is in the middle of MFA setup: either a
    signed-in user adding a method (optionally, or because an admin was
    forced here post-login by TwoFactorMiddleware), or — mirroring
    two_factor_verify — someone whose password already checked out but who
    has no MFA configured yet and so isn't fully logged in here."""
    if request.user.is_authenticated:
        return request.user, False
    uid = request.session.get("pre_2fa_user")
    if uid:
        user = User.objects.filter(pk=uid).first()
        if user:
            return user, True
    return None, False


def _webauthn_rp_id(request):
    """Relying-party ID: just the current request's hostname (no scheme or
    port). Derived per-request rather than a fixed setting — a browser only
    ever accepts an rp_id equal to the page's own domain anyway, so there's
    nothing to configure beyond what's already serving the app."""
    return request.get_host().split(":")[0]


def _webauthn_origin(request):
    scheme = "https" if request.is_secure() else "http"
    return "{}://{}".format(scheme, request.get_host())


def _user_credential_descriptors(user):
    from webauthn.helpers.structs import PublicKeyCredentialDescriptor
    return [
        PublicKeyCredentialDescriptor(id=bytes(c.credential_id))
        for c in WebAuthnCredential.objects.filter(user=user)
    ]


def two_factor_verify(request):
    """Second login step: a passkey (the default method) or an authenticator
    code (the secondary one) — either satisfies it. Reached from login_view
    for users who have some MFA method enabled (they are not yet logged in
    here). The passkey ceremony itself runs via passkey_auth_options/
    passkey_auth_verify below; this view only ever handles the code form."""
    uid = request.session.get("pre_2fa_user")
    user = User.objects.filter(pk=uid).first() if uid else None
    has_passkey = user is not None and WebAuthnCredential.objects.filter(user=user).exists()
    device = (
        TOTPDevice.objects.filter(user_id=uid, confirmed=True).first()
        if user is not None else None
    )
    if user is None or (not has_passkey and not device):
        request.session.pop("pre_2fa_user", None)
        return redirect("login")
    error = None
    if request.method == "POST":
        if _twofa_throttled(uid):
            error = "Too many attempts — wait a few minutes and try again."
        elif device and _totp_valid(device.secret, request.POST.get("code", "")):
            nxt = _safe_next(request.session.pop("pre_2fa_next", "") or "")
            request.session.pop("pre_2fa_user", None)
            login(request, user)
            return redirect(nxt or "location_list")
        else:
            _twofa_record_failure(uid)
            error = "That code didn't match. Try again."
    return render(request, "registration/two_factor_verify.html", {
        "error": error,
        "has_passkey": has_passkey,
        "has_totp": device is not None,
    })


@require_POST
def passkey_auth_options(request):
    """Step 1 of the passkey login ceremony: generate a WebAuthn
    authentication challenge scoped to the pending user's own credentials."""
    uid = request.session.get("pre_2fa_user")
    user = User.objects.filter(pk=uid).first() if uid else None
    if user is None:
        return JsonResponse({"error": "Session expired — please log in again."}, status=400)
    from webauthn import generate_authentication_options, options_to_json
    from webauthn.helpers import bytes_to_base64url
    from webauthn.helpers.structs import UserVerificationRequirement

    options = generate_authentication_options(
        rp_id=_webauthn_rp_id(request),
        allow_credentials=_user_credential_descriptors(user),
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    request.session["passkey_auth_challenge"] = bytes_to_base64url(options.challenge)
    return HttpResponse(options_to_json(options), content_type="application/json")


@require_POST
def passkey_auth_verify(request):
    """Step 2: verify the browser's assertion and, on success, complete login
    exactly like a correct TOTP code would."""
    uid = request.session.get("pre_2fa_user")
    user = User.objects.filter(pk=uid).first() if uid else None
    if user is None:
        return JsonResponse({"error": "Session expired — please log in again."}, status=400)
    if _twofa_throttled(uid):
        return JsonResponse({"error": "Too many attempts — wait a few minutes and try again."}, status=429)
    challenge_b64 = request.session.get("passkey_auth_challenge")
    if not challenge_b64:
        return JsonResponse({"error": "No pending passkey challenge — try again."}, status=400)
    try:
        body = json.loads(request.body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return JsonResponse({"error": "Malformed request."}, status=400)

    from webauthn.helpers import base64url_to_bytes
    try:
        credential_id = base64url_to_bytes(body.get("rawId") or "")
    except Exception:
        return JsonResponse({"error": "Malformed credential."}, status=400)

    cred = WebAuthnCredential.objects.filter(user=user, credential_id=credential_id).first()
    if not cred:
        _twofa_record_failure(uid)
        return JsonResponse({"error": "Unrecognized passkey."}, status=400)

    from webauthn import verify_authentication_response
    try:
        verification = verify_authentication_response(
            credential=body,
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_rp_id=_webauthn_rp_id(request),
            expected_origin=_webauthn_origin(request),
            credential_public_key=bytes(cred.public_key),
            credential_current_sign_count=cred.sign_count,
        )
    except Exception:
        logger.exception("Passkey authentication verification failed for user %s", user.pk)
        _twofa_record_failure(uid)
        return JsonResponse({"error": "That passkey didn't verify. Try again."}, status=400)

    cred.sign_count = verification.new_sign_count
    cred.last_used_at = timezone.now()
    cred.save(update_fields=["sign_count", "last_used_at"])

    request.session.pop("passkey_auth_challenge", None)
    nxt = _safe_next(request.session.pop("pre_2fa_next", "") or "")
    request.session.pop("pre_2fa_user", None)
    login(request, user)
    return JsonResponse({"redirect": nxt or reverse("location_list")})


def two_factor_setup(request):
    """Entry point for setting up MFA: a passkey (the default/recommended
    method) or an authenticator app (the secondary one). Works both for a
    signed-in user adding a method optionally, and for an admin who was sent
    here (still pending login) because MFA is required."""
    user, pending = _setup_target_user(request)
    if user is None:
        return redirect("login")
    if user_has_mfa(user):
        # Already has a method — nothing to force. A pending user shouldn't
        # normally reach this page at all (login_view would have sent them
        # to verify instead), but don't strand them here if they do.
        return redirect("two_factor_verify" if pending else "two_factor_settings")
    return render(request, "registration/two_factor_setup.html", {"required": user.is_staff})


def two_factor_setup_totp(request):
    """Authenticator-app setup/confirm — the secondary MFA method."""
    import pyotp
    user, pending = _setup_target_user(request)
    if user is None:
        return redirect("login")

    device, _ = TOTPDevice.objects.get_or_create(
        user=user, defaults={"secret": pyotp.random_base32()}
    )
    if device.confirmed:
        return redirect("location_list" if pending else "two_factor_settings")

    error = None
    if request.method == "POST":
        if _totp_valid(device.secret, request.POST.get("code", "")):
            device.confirmed = True
            device.save(update_fields=["confirmed"])
            messages.success(request, "Two-factor authentication is now enabled.")
            if pending:
                nxt = _safe_next(request.session.pop("pre_2fa_next", "") or "")
                request.session.pop("pre_2fa_user", None)
                login(request, user)
                return redirect(nxt or "location_list")
            # Continue into the app rather than dead-ending on a settings page
            # (matters most for admins who were forced here mid-navigation).
            return redirect("location_list")
        error = "That code didn't match — check your device's time and try again."

    return render(request, "registration/two_factor_setup_totp.html", {
        "qr": _totp_qr_data_uri(device.secret, user),
        "secret": device.secret,
        "error": error,
        "required": user.is_staff,
    })


def two_factor_setup_passkey(request):
    """Passkey setup — the default MFA method. The actual WebAuthn ceremony
    runs client-side against passkey_register_options/passkey_register_verify
    below; this just renders the page (and confirms there's actually someone
    pending/signed-in to set it up for)."""
    user, pending = _setup_target_user(request)
    if user is None:
        return redirect("login")
    return render(request, "registration/two_factor_setup_passkey.html", {"required": user.is_staff})


@require_POST
def passkey_register_options(request):
    """Step 1 of registering a passkey: generate a WebAuthn registration
    challenge for whoever is mid-setup (see _setup_target_user)."""
    user, pending = _setup_target_user(request)
    if user is None:
        return JsonResponse({"error": "Please log in again."}, status=400)
    from webauthn import generate_registration_options, options_to_json
    from webauthn.helpers import bytes_to_base64url
    from webauthn.helpers.cose import COSEAlgorithmIdentifier
    from webauthn.helpers.structs import AuthenticatorSelectionCriteria, ResidentKeyRequirement

    options = generate_registration_options(
        rp_id=_webauthn_rp_id(request),
        rp_name="Waypoint",
        user_id=str(user.pk).encode(),
        user_name=user.username,
        user_display_name=user.email or user.username,
        exclude_credentials=_user_credential_descriptors(user),
        # Discoverable (resident) credentials are what let a browser offer
        # "sign in with a passkey" without a username typed in first.
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
        ),
        # ES256 only: offering the full default algorithm list (EdDSA, ES512,
        # various RSA variants) has been seen to make some passkey providers
        # (e.g. Bitwarden's) fail outright during creation with an opaque
        # vendor error, rather than just picking the one they do support.
        # ES256 alone is already supported essentially everywhere.
        supported_pub_key_algs=[COSEAlgorithmIdentifier.ECDSA_SHA_256],
    )
    request.session["passkey_reg_challenge"] = bytes_to_base64url(options.challenge)
    request.session["passkey_reg_user"] = user.pk
    return HttpResponse(options_to_json(options), content_type="application/json")


@require_POST
def passkey_register_verify(request):
    """Step 2: verify the browser's attestation response and save the
    resulting credential. For a pending (not-yet-logged-in) admin forced
    through setup, this also completes their login."""
    user, pending = _setup_target_user(request)
    if user is None or request.session.get("passkey_reg_user") != user.pk:
        return JsonResponse({"error": "Please log in again."}, status=400)
    challenge_b64 = request.session.get("passkey_reg_challenge")
    if not challenge_b64:
        return JsonResponse({"error": "No pending passkey registration — try again."}, status=400)
    try:
        body = json.loads(request.body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return JsonResponse({"error": "Malformed request."}, status=400)
    name = (body.pop("_name", "") or "").strip()[:100]

    from webauthn import verify_registration_response
    from webauthn.helpers import base64url_to_bytes
    try:
        verification = verify_registration_response(
            credential=body,
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_rp_id=_webauthn_rp_id(request),
            expected_origin=_webauthn_origin(request),
        )
    except Exception:
        logger.exception(
            "Passkey registration verification failed for user %s (rp_id=%r origin=%r)",
            user.pk, _webauthn_rp_id(request), _webauthn_origin(request),
        )
        return JsonResponse({"error": "That passkey couldn't be registered. Try again."}, status=400)

    WebAuthnCredential.objects.create(
        user=user,
        credential_id=verification.credential_id,
        public_key=verification.credential_public_key,
        sign_count=verification.sign_count,
        name=name,
    )
    request.session.pop("passkey_reg_challenge", None)
    request.session.pop("passkey_reg_user", None)

    redirect_url = reverse("two_factor_settings")
    if pending:
        nxt = _safe_next(request.session.pop("pre_2fa_next", "") or "")
        request.session.pop("pre_2fa_user", None)
        login(request, user)
        redirect_url = nxt or reverse("location_list")
    else:
        messages.success(request, "Passkey added.")
    return JsonResponse({"redirect": redirect_url})


@login_required
def two_factor_settings(request):
    passkeys = list(WebAuthnCredential.objects.filter(user=request.user))
    totp_enabled = TOTPDevice.objects.filter(user=request.user, confirmed=True).exists()
    return render(request, "registration/two_factor_settings.html", {
        "passkeys": passkeys,
        "totp_enabled": totp_enabled,
        "required": request.user.is_staff,
    })


@login_required
@require_POST
def two_factor_disable(request):
    """Turns off the authenticator-app (TOTP) method specifically — a
    separate passkey, if any, is untouched. Blocked only if this would leave
    an admin with no MFA method at all."""
    if request.user.is_staff and not WebAuthnCredential.objects.filter(user=request.user).exists():
        messages.error(request, "Admins must have at least one MFA method — set up a passkey first.")
        return redirect("two_factor_settings")
    TOTPDevice.objects.filter(user=request.user).delete()
    messages.success(request, "Authenticator app disabled.")
    return redirect("two_factor_settings")


@login_required
@require_POST
def passkey_delete(request, pk):
    """Removes one passkey. Blocked only if this would leave an admin with no
    MFA method at all (another passkey or a confirmed TOTP device is fine)."""
    cred = get_object_or_404(WebAuthnCredential, pk=pk, user=request.user)
    if request.user.is_staff:
        other_passkey = WebAuthnCredential.objects.filter(user=request.user).exclude(pk=cred.pk).exists()
        totp_enabled = TOTPDevice.objects.filter(user=request.user, confirmed=True).exists()
        if not other_passkey and not totp_enabled:
            messages.error(request, "Admins must have at least one MFA method — set up another one first.")
            return redirect("two_factor_settings")
    cred.delete()
    messages.success(request, "Passkey removed.")
    return redirect("two_factor_settings")


def _make_admin_if_first(user):
    """The very first account to exist becomes the site admin automatically."""
    if User.objects.count() == 1:  # this user is the only one
        user.is_staff = True
        user.is_superuser = True
        user.save(update_fields=["is_staff", "is_superuser"])


@ratelimit("captcha", 40, 60)
def captcha_image(request):
    """Serve a fresh registration CAPTCHA, stashing the answer in the session.
    Public (registration is anonymous); rate-limited so it can't be hammered."""
    from time import time
    from . import captcha as captcha_mod
    text = captcha_mod.make_text()
    request.session[captcha_mod.SESSION_ANSWER] = text
    request.session[captcha_mod.SESSION_TIME] = int(time())
    resp = HttpResponse(captcha_mod.render_image(text), content_type="image/png")
    resp["Cache-Control"] = "no-store, max-age=0, must-revalidate"
    return resp


def register_view(request):
    if request.user.is_authenticated:
        return redirect("location_list")
    form = RegisterForm(request.POST or None, request=request)
    if request.method == "POST" and form.is_valid():
        # One-time use: clear the solved challenge so it can't be replayed.
        from . import captcha as captcha_mod
        request.session.pop(captcha_mod.SESSION_ANSWER, None)
        request.session.pop(captcha_mod.SESSION_TIME, None)
        if not settings.REQUIRE_EMAIL_VERIFICATION:
            # Verification disabled — create the account directly.
            user = form.save()
            _make_admin_if_first(user)
            EmailVerification.objects.get_or_create(user=user, defaults={"verified": True})
            # Terms were agreed via the registration checkbox.
            TermsAcceptance.objects.get_or_create(
                user=user, version=settings.TERMS_VERSION,
                defaults={"ip_address": _get_ip(request)},
            )
            login(request, user)
            request.session["tos_accepted_version"] = settings.TERMS_VERSION
            messages.success(request, "Welcome, {}!".format(user.username))
            return redirect("location_list")

        # Verify-first: store a pending signup and email a confirmation link.
        # No User account is created until the email is confirmed.
        import secrets
        from django.contrib.auth.hashers import make_password
        PendingRegistration.objects.filter(email__iexact=form.cleaned_data["email"]).delete()
        pending = PendingRegistration.objects.create(
            username=form.cleaned_data["username"],
            email=form.cleaned_data["email"],
            password=make_password(form.cleaned_data["password1"]),
            token=secrets.token_urlsafe(32),
        )
        _send_registration_email(request, pending)
        return render(request, "registration/register_pending.html", {"email": pending.email})
    return render(request, "registration/register.html", {"form": form})


# ── Registration email confirmation (verify-first) ─────────────────────────────

_REGISTER_MAX_AGE_DAYS = 3


def _send_registration_email(request, pending):
    link = request.build_absolute_uri(
        "{}?token={}".format(reverse("register_confirm"), pending.token)
    )
    body = (
        "Hi {},\n\n"
        "Confirm your email to finish creating your Waypoint account:\n\n"
        "{}\n\n"
        "This link expires in {} days. If you didn't request this, ignore this email.\n".format(
            pending.username, link, _REGISTER_MAX_AGE_DAYS
        )
    )
    try:
        send_mail("Confirm your Waypoint registration", body,
                  settings.DEFAULT_FROM_EMAIL, [pending.email], fail_silently=False)
    except Exception:
        pass


def register_confirm(request):
    """Create the real account once the emailed link is opened."""
    token = request.GET.get("token", "")
    pending = PendingRegistration.objects.filter(token=token).first()
    if pending is None:
        messages.error(request, "That confirmation link is invalid or already used.")
        return redirect("register")

    if (timezone.now() - pending.created_at).days > _REGISTER_MAX_AGE_DAYS:
        pending.delete()
        messages.error(request, "That confirmation link has expired. Please register again.")
        return redirect("register")

    # Guard against the username/email being taken between request and confirm.
    if (User.objects.filter(username__iexact=pending.username).exists()
            or User.objects.filter(email__iexact=pending.email).exists()):
        pending.delete()
        messages.info(request, "That account already exists — please sign in.")
        return redirect("login")

    user = User(username=pending.username, email=pending.email, password=pending.password)
    user.save()
    _make_admin_if_first(user)
    EmailVerification.objects.create(user=user, verified=True, verified_at=timezone.now())
    # Terms were agreed via the registration checkbox.
    TermsAcceptance.objects.get_or_create(
        user=user, version=settings.TERMS_VERSION,
        defaults={"ip_address": _get_ip(request)},
    )
    pending.delete()
    login(request, user)
    request.session["email_verified"] = True
    request.session["tos_accepted_version"] = settings.TERMS_VERSION
    messages.success(request, "Welcome, {}! Your email is verified.".format(user.username))
    return redirect("location_list")


# ── Email verification ────────────────────────────────────────────────────────

_EMAIL_VERIFY_SALT = "wp-email-verify"
_EMAIL_VERIFY_MAX_AGE = 60 * 60 * 24 * 3   # 3 days


def _send_verification_email(request, user):
    if not user.email:
        return False
    token = signing.dumps({"uid": user.pk, "email": user.email}, salt=_EMAIL_VERIFY_SALT)
    link = request.build_absolute_uri(
        "{}?token={}".format(reverse("verify_email_confirm"), token)
    )
    body = (
        "Hi {},\n\n"
        "Please confirm your email address for Waypoint by opening this link:\n\n"
        "{}\n\n"
        "This link expires in 3 days. If you didn't create a Waypoint account, "
        "you can ignore this email.\n".format(user.username, link)
    )
    try:
        send_mail(
            "Confirm your Waypoint email",
            body,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )
        EmailVerification.objects.update_or_create(
            user=user, defaults={"last_sent_at": timezone.now()}
        )
        return True
    except Exception:
        return False


@login_required
def verify_email(request):
    """Landing page telling the user to check their email, with resend + the
    option to set/correct the address. The middleware sends them here."""
    ev, _ = EmailVerification.objects.get_or_create(user=request.user)
    if ev.verified:
        request.session["email_verified"] = True
        return redirect("location_list")
    return render(request, "registration/verify_email.html", {"email": request.user.email})


@require_POST
@login_required
def verify_email_resend(request):
    # Allow the user to set/correct their email here if it's missing or wrong.
    new_email = (request.POST.get("email") or "").strip()
    if new_email:
        if User.objects.filter(email__iexact=new_email).exclude(pk=request.user.pk).exists():
            messages.error(request, "That email is already in use by another account.")
            return redirect("verify_email")
        request.user.email = new_email
        request.user.save(update_fields=["email"])
    if _send_verification_email(request, request.user):
        messages.success(request, "Verification email sent to {}.".format(request.user.email))
    else:
        messages.error(request, "Couldn't send the email — add a valid address below.")
    return redirect("verify_email")


def verify_email_confirm(request):
    """Validate the emailed token and mark the user's email verified. Works
    even if the user is logged out (the token identifies the account)."""
    token = request.GET.get("token", "")
    try:
        data = signing.loads(token, salt=_EMAIL_VERIFY_SALT, max_age=_EMAIL_VERIFY_MAX_AGE)
        user = User.objects.get(pk=data["uid"])
        if user.email != data["email"]:
            raise ValueError("email changed")
    except Exception:
        messages.error(request, "That verification link is invalid or has expired. Please resend.")
        return redirect("verify_email" if request.user.is_authenticated else "login")

    EmailVerification.objects.update_or_create(
        user=user, defaults={"verified": True, "verified_at": timezone.now()}
    )
    if request.user.is_authenticated and request.user.pk == user.pk:
        request.session["email_verified"] = True
    messages.success(request, "Your email is verified — thanks!")
    return redirect("location_list" if request.user.is_authenticated else "login")


# ── Help / glossary ───────────────────────────────────────────────────────────

@login_required
def help_page(request):
    """A glossary of the app's concepts with links to each feature. The content
    lives in templates/tracker/help.html; keep it updated when features change
    (its links use {% url %} so they follow route renames automatically)."""
    return render(request, "tracker/help.html")


# ── Terms of Service ──────────────────────────────────────────────────────────

def terms(request):
    """Show the Terms of Service and, for signed-in users, the accept/decline
    controls. The TermsAcceptanceMiddleware sends unaccepted users here."""
    current = settings.TERMS_VERSION
    accepted = None
    if request.user.is_authenticated:
        accepted = TermsAcceptance.objects.filter(user=request.user, version=current).first()
    return render(request, "legal/terms.html", {
        "terms_version": current,
        "accepted": accepted,
        "next": request.GET.get("next", ""),
    })


@login_required
@require_POST
def terms_accept(request):
    TermsAcceptance.objects.get_or_create(
        user=request.user,
        version=settings.TERMS_VERSION,
        defaults={"ip_address": _get_ip(request)},
    )
    request.session["tos_accepted_version"] = settings.TERMS_VERSION
    messages.success(request, "Thanks — you're all set.")
    nxt = _safe_next(request.POST.get("next", ""))
    if nxt:
        return redirect(nxt)
    return redirect("location_list")


@login_required
@require_POST
def terms_decline(request):
    logout(request)
    messages.info(request, "You must accept the Terms of Service to use Waypoint.")
    return redirect("login")


# ── Friend group ratings ────────────────────────────────────────────────────
# Groups are private (see FriendGroup below); a waypoint's per-group rating
# breakdown is only ever computed relative to the CURRENT user's own group
# memberships, so it can never leak another user's group membership or another
# group's data — only groups the viewer is themselves a member of.

def _my_groups_with_members(user):
    """[(FriendGroup, {member user_id, ...}), ...] for every group `user` belongs to."""
    if not user.is_authenticated:
        return []
    group_ids = FriendGroupMembership.objects.filter(user=user).values_list("group_id", flat=True)
    groups = FriendGroup.objects.filter(pk__in=group_ids).order_by("name")
    return [
        (g, set(FriendGroupMembership.objects.filter(group=g).values_list("user_id", flat=True)))
        for g in groups
    ]


def _bulk_group_rating_breakdown(user, location_ids):
    """{location_id: [{'group': FriendGroup, 'avg': float, 'count': int}, ...]}
    — one query regardless of how many locations, restricted to the given ids."""
    my_groups = _my_groups_with_members(user)
    if not my_groups or not location_ids:
        return {}
    all_member_ids = set().union(*(ids for _, ids in my_groups))
    reviews = LocationReview.objects.filter(
        location_id__in=location_ids, user_id__in=all_member_ids
    ).values("location_id", "user_id", "rating")
    by_location = {}
    for r in reviews:
        by_location.setdefault(r["location_id"], []).append(r)
    result = {}
    for loc_id, revs in by_location.items():
        breakdown = []
        for group, member_ids in my_groups:
            ratings = [r["rating"] for r in revs if r["user_id"] in member_ids]
            if ratings:
                breakdown.append({
                    "group": group,
                    "avg": round(float(sum(ratings) / len(ratings)), 1),
                    "count": len(ratings),
                })
        if breakdown:
            result[loc_id] = breakdown
    return result


def _group_rating_summary_text(breakdown):
    """Compact one-liner for map popups/list cards/search results, where a
    full per-group breakdown would take up too much space."""
    if not breakdown:
        return None
    avgs = [b["avg"] for b in breakdown]
    if len(avgs) == 1:
        return "Group rating: {:.1f}".format(avgs[0])
    return "Group ratings range: {:.1f}–{:.1f}".format(min(avgs), max(avgs))


# ── Locations ─────────────────────────────────────────────────────────────────

@login_required
@ratelimit("home", 60, 60)
def location_list(request):
    my_reviews = LocationReview.objects.filter(location=OuterRef("pk"), user=request.user)
    locations = (
        Location.objects
        .prefetch_related("photos", "items", "collections")
        .annotate(
            user_avg_rating=Avg("reviews__rating"),
            user_review_count=Count("reviews", distinct=True),
            mine=Exists(my_reviews),
        )
        .all()
    )

    # A compact, JSON-serialisable snapshot of every waypoint. The default
    # (list) view renders entirely from this payload client-side — sorting,
    # filtering and paging happen in the browser with no extra requests, so
    # loading the home page costs zero Google API calls.
    loc_list = list(locations)
    group_breakdowns = _bulk_group_rating_breakdown(request.user, [loc.pk for loc in loc_list])
    waypoints = []
    for loc in loc_list:
        rating = loc.user_avg_rating if loc.user_avg_rating is not None else loc.overall_rating
        first_photo = next(iter(loc.photos.all()), None)
        waypoints.append({
            "id": loc.pk,
            "name": loc.name,
            "gluten_free": loc.gluten_free,
            "mine": bool(loc.mine),
            "rating": round(float(rating), 1) if rating else None,
            "review_count": loc.user_review_count,
            "google_place_id": loc.google_place_id or "",
            "group_rating_summary": _group_rating_summary_text(group_breakdowns.get(loc.pk)),
            "lat": float(loc.latitude) if loc.latitude is not None else None,
            "lng": float(loc.longitude) if loc.longitude is not None else None,
            "city": loc.city,
            "state": loc.state,
            "address": loc.address,
            "photo": first_photo.image.url if first_photo else None,
            "created": int(loc.created_at.timestamp()),
            "url": "/locations/{}/".format(loc.pk),
        })

    return render(request, "tracker/location_list.html", {
        "locations": locations,
        "waypoints": waypoints,
        "gf_choices": Location.GF_CHOICES,
    })


@login_required
@ratelimit("loc_detail", 90, 60)
def location_detail(request, pk):
    location = get_object_or_404(
        Location.objects.prefetch_related(
            "photos", "items__reviews__user", "items__reviews__submitted_by",
            "reviews__user", "reviews__submitted_by", "collections",
        ),
        pk=pk,
    )
    my_review = location.reviews.filter(user=request.user).first()
    my_item_reviews = {
        rev.item_id: rev
        for rev in ItemReview.objects.filter(
            item__in=_item_queryset_for_location(location), user=request.user
        ).select_related("item")
    }
    # "Rate Me!" from the map lands here with ?rate=1 to open the review form
    open_review = request.GET.get("rate") == "1"
    gf_my_vote = location.gf_votes.filter(user=request.user).first()

    # Chain-linking: other waypoints with the same name (case-insensitive) not
    # already in this one's chain group — candidates to link as branches of
    # the same chain. And the branches already linked, if any.
    chain_candidates = Location.objects.filter(name__iexact=location.name).exclude(pk=location.pk)
    if location.chain_group_id:
        chain_candidates = chain_candidates.exclude(chain_group_id=location.chain_group_id)
    chain_candidates = list(chain_candidates.order_by("city", "address")[:20])
    chain_linked = (
        list(location.chain_group.locations.exclude(pk=location.pk).order_by("city", "address"))
        if location.chain_group_id else []
    )

    group_rating_breakdown = _bulk_group_rating_breakdown(request.user, [location.pk]).get(location.pk, [])

    # Public, superuser/admin-featured collections this waypoint belongs to
    # (e.g. a company's "Food Trucks" list) — linked from the page for anyone
    # to discover the rest of the collection's waypoints from here.
    featured_collections = location.collections.filter(is_public=True, is_featured=True)

    # Materialized once so the items_section partial and its on-behalf targets
    # agree on the same list.
    items = list(_annotated_items(location))

    return render(request, "tracker/location_detail.html", {
        "location": location,
        "item_form": ItemForm(),
        "photo_form": PhotoForm(location=location),
        "my_review": my_review,
        "gf_my_vote": gf_my_vote,
        "all_collections": Collection.objects.filter(created_by=request.user),
        # Needed by the items_section partial so existing dishes render on load
        "items": items,
        "item_behalf_targets": _item_behalf_targets(request, location, items),
        "linked_targets": _location_linked_targets(request, location),
        "my_reviews": my_item_reviews,
        # Auto-open the location review form when arriving via "Rate Me!"
        "open_review": open_review,
        "location_review_form": LocationReviewForm(instance=my_review) if open_review else None,
        "chain_candidates": chain_candidates,
        "chain_linked": chain_linked,
        "group_rating_breakdown": group_rating_breakdown,
        "can_edit": can_edit_location(request.user, location),
        "featured_collections": featured_collections,
    })


@login_required
def location_create(request):
    prefill = {f: request.GET[f] for f in [
        'name','address','latitude','longitude','city','state',
        'gluten_free','dietary_notes','google_place_id',
    ] if request.GET.get(f)}
    unlock = is_superuser_role(request.user)
    form = LocationForm(request.POST or None, initial=prefill or None, unlock_google_fields=unlock)
    if request.method == "POST" and form.is_valid():
        location = form.save(commit=False)
        location.created_by = request.user
        location.save()
        _log(request, AuditLog.ACTION_CREATE, location, 'Created location "{}"'.format(location.name))
        messages.success(request, "Waypoint added.")
        return redirect("location_detail", pk=location.pk)
    return render(request, "tracker/location_form.html", {"form": form, "action": "Add"})


@login_required
@require_POST
def rate_poi(request):
    """Get-or-create a waypoint from a Google POI, then open its rating form.

    Reached from the map's "Rate Me!" button. Matches an existing waypoint by
    Google Place ID so the same POI isn't duplicated on repeated rating.
    """
    place_id = (request.POST.get("google_place_id") or "").strip()
    name = (request.POST.get("name") or "").strip()[:255]

    location = Location.objects.filter(google_place_id=place_id).first() if place_id else None
    if location is None:
        if not name:
            messages.error(request, "Couldn't identify that place to rate.")
            return redirect("location_list")
        location = Location.objects.create(
            name=name,
            latitude=request.POST.get("latitude") or None,
            longitude=request.POST.get("longitude") or None,
            address=(request.POST.get("address") or "").strip(),
            google_place_id=place_id,
            created_by=request.user,
        )
        _log(request, AuditLog.ACTION_CREATE, location,
             'Added "{}" from the map to rate it'.format(location.name))

    return redirect("{}?rate=1#location-reviews".format(
        reverse("location_detail", args=[location.pk])))


@login_required
def location_edit(request, pk):
    location = get_object_or_404(Location, pk=pk)
    if not can_edit_location(request.user, location):
        return HttpResponseForbidden("Only the creator, a superuser, or an admin can edit this waypoint.")
    unlock = is_superuser_role(request.user)
    if request.method == "POST":
        # Snapshot the stored values BEFORE binding — ModelForm.is_valid()
        # mutates `location` in place, so we'd otherwise diff it against itself.
        old = Location.objects.get(pk=location.pk)
        form = LocationForm(request.POST, instance=location, unlock_google_fields=unlock)
        if form.is_valid():
            diff = _location_diff(old, form.cleaned_data)
            form.save()
            if diff != "No changes detected":   # only log real changes
                _log(request, AuditLog.ACTION_UPDATE, location, diff)
            messages.success(request, "Waypoint updated.")
            return redirect("location_detail", pk=location.pk)
    else:
        form = LocationForm(instance=location, unlock_google_fields=unlock)
    return render(request, "tracker/location_form.html", {
        "form": form,
        "action": "Edit",
        "location": location,
        # True when a superuser/admin is editing a normally-locked Google POI
        "admin_override": unlock and bool(location.google_place_id),
    })


@login_required
def location_delete(request, pk):
    location = get_object_or_404(Location, pk=pk)
    if not can_delete(request.user, location.created_by):
        return HttpResponseForbidden("Only the creator, a superuser, or an admin can delete this waypoint.")
    # Lets the admin dashboard link here with ?next=... so deleting (or
    # cancelling) returns there instead of always landing on location_list.
    nxt = _safe_next(request.POST.get("next") or request.GET.get("next") or "")
    if request.method == "POST":
        reason = (request.POST.get("reason") or "").strip()
        if not reason:
            messages.error(request, "Please provide a reason for deleting this waypoint.")
            return render(request, "tracker/location_confirm_delete.html", {"location": location, "next": nxt})
        # If this location is chain-linked, items it happens to "own" (Item.
        # location) are still shared with the rest of the group — reassign
        # them to a surviving branch instead of letting CASCADE delete them.
        if location.chain_group_id:
            sibling = location.chain_group.locations.exclude(pk=location.pk).first()
            if sibling:
                Item.objects.filter(location=location).update(location=sibling)
        _log(
            request,
            AuditLog.ACTION_DELETE,
            location,
            'Deleted location "{}" — reason: {}'.format(location.name, reason),
        )
        location.delete()
        messages.success(request, "Waypoint deleted.")
        return redirect(nxt or "location_list")
    return render(request, "tracker/location_confirm_delete.html", {"location": location, "next": nxt})


def _merge_chain_group_items(group):
    """After grouping, collapse same-named (case-insensitive) items across
    the group's locations into one shared Item, moving reviews over (a user
    who'd already reviewed both copies keeps only the one on the survivor).
    Returns (merged_items, dropped_reviews) so the caller can audit-log the
    destructive part."""
    items = Item.objects.filter(location__chain_group_id=group.pk).order_by("pk")
    kept_by_name = {}
    merged_items = 0
    dropped_reviews = 0
    for item in items:
        key = item.name.strip().lower()
        keeper = kept_by_name.get(key)
        if keeper is None:
            kept_by_name[key] = item
            continue
        for review in item.reviews.all():
            if ItemReview.objects.filter(item=keeper, user_id=review.user_id).exists():
                review.delete()   # user already reviewed the surviving item — drop the dupe
                dropped_reviews += 1
            else:
                review.item = keeper
                review.save(update_fields=["item"])
        item.delete()
        merged_items += 1
    return merged_items, dropped_reviews


@login_required
@ratelimit("chain_search", 30, 60, json=True)
def location_chain_search(request, pk):
    """Name search (substring, not exact) for picking a waypoint to chain-link
    — unlike the auto-detected candidates on the location page, this isn't
    limited to waypoints sharing the exact same name (e.g. lets "Starbucks -
    Main St" find and link to "Starbucks Ocean Ave")."""
    location = get_object_or_404(Location, pk=pk)
    q = (request.GET.get("q") or "").strip()
    if len(q) < 2:
        return JsonResponse({"results": []})
    qs = Location.objects.exclude(pk=location.pk)
    if location.chain_group_id:
        qs = qs.exclude(chain_group_id=location.chain_group_id)
    qs = qs.filter(name__icontains=q).order_by("name")[:10]
    return JsonResponse({"results": [
        {"id": loc.pk, "name": loc.name, "city": loc.city, "state": loc.state}
        for loc in qs
    ]})


@login_required
@require_POST
def location_link(request, pk, target_pk):
    """Link two waypoints (e.g. two Burger King branches) into a shared chain
    group, so their items/dishes and item reviews are pooled. Location-level
    info (address, hours, its own rating/reviews) stays put."""
    location = get_object_or_404(Location, pk=pk)
    target = get_object_or_404(Location, pk=target_pk)
    # Linking is destructive (merges/deletes shared items + reviews globally),
    # so require edit rights on the waypoint being acted from.
    if not can_edit_location(request.user, location):
        return HttpResponseForbidden(
            "Only the creator, a superuser, or an admin can chain-link this waypoint."
        )

    if location.chain_group_id and target.chain_group_id:
        if location.chain_group_id != target.chain_group_id:
            old_group_id = target.chain_group_id
            Location.objects.filter(chain_group_id=old_group_id).update(chain_group_id=location.chain_group_id)
            ChainGroup.objects.filter(pk=old_group_id).delete()
    elif location.chain_group_id:
        target.chain_group_id = location.chain_group_id
        target.save(update_fields=["chain_group_id"])
    elif target.chain_group_id:
        location.chain_group_id = target.chain_group_id
        location.save(update_fields=["chain_group_id"])
    else:
        group = ChainGroup.objects.create()
        Location.objects.filter(pk__in=[location.pk, target.pk]).update(chain_group_id=group.pk)

    location.refresh_from_db()
    merged_items, dropped_reviews = _merge_chain_group_items(location.chain_group)
    detail = 'Linked "{}" with "{}" as the same chain'.format(location.name, target.name)
    if merged_items or dropped_reviews:
        detail += " (merged {} duplicate item(s), dropped {} duplicate review(s))".format(
            merged_items, dropped_reviews)
    _log(request, AuditLog.ACTION_UPDATE, location, detail)
    messages.success(request, 'Linked with "{}" — their items/dishes are now shared.'.format(target.name))
    return redirect("location_detail", pk=location.pk)


@login_required
@require_POST
def location_unlink(request, pk):
    """Remove this waypoint from its chain group. Items it originally added
    stay with it; items only visible via other branches stop showing here.
    Superuser/admin only — more restrictive than linking, since detaching can
    silently drop item reviews that were merged in when the chain was formed."""
    location = get_object_or_404(Location, pk=pk)
    if not is_superuser_role(request.user):
        return HttpResponseForbidden("Only a superuser or admin can detach a waypoint from its chain.")
    group = location.chain_group
    if not group:
        return redirect("location_detail", pk=location.pk)
    location.chain_group = None
    location.save(update_fields=["chain_group"])
    if group.locations.count() < 2:
        Location.objects.filter(chain_group_id=group.pk).update(chain_group_id=None)
        group.delete()
    _log(request, AuditLog.ACTION_UPDATE, location,
         'Unlinked "{}" from its chain group'.format(location.name))
    messages.success(request, "Unlinked from the chain group.")
    return redirect("location_detail", pk=location.pk)


@login_required
@require_POST
def gf_vote(request, pk):
    """Cast/toggle the current user's agree/disagree vote on a location's GF
    status. Re-voting the same way clears the vote. Re-renders the GF card."""
    location = get_object_or_404(Location, pk=pk)
    choice = request.POST.get("vote")   # "agree" | "disagree"
    existing = GlutenFreeVote.objects.filter(location=location, user=request.user).first()

    if choice in ("agree", "disagree"):
        agrees = choice == "agree"
        if existing and existing.agrees == agrees:
            existing.delete()                       # clicking the same vote un-votes
            detail = "Cleared GF vote"
        elif existing:
            existing.agrees = agrees
            existing.save(update_fields=["agrees", "updated_at"])
            detail = "Changed GF vote to {}".format(choice)
        else:
            GlutenFreeVote.objects.create(location=location, user=request.user, agrees=agrees)
            detail = "Voted {} on GF status".format(choice)
        _log(request, AuditLog.ACTION_UPDATE, location, detail)

    gf_my_vote = GlutenFreeVote.objects.filter(location=location, user=request.user).first()
    return render(request, "tracker/partials/gf_card.html", {
        "location": location, "gf_my_vote": gf_my_vote,
    })


@login_required
@ratelimit("geojson", 30, 60, json=True)
def locations_geojson(request):
    my_reviews = LocationReview.objects.filter(location=OuterRef("pk"), user=request.user)
    qs = (
        Location.objects
        .exclude(latitude=None).exclude(longitude=None)
        .annotate(
            user_avg_rating=Avg("reviews__rating"),
            num_reviews=Count("reviews", distinct=True),
            mine=Exists(my_reviews),
        )
        .prefetch_related("photos")
    )
    loc_list = list(qs)
    group_breakdowns = _bulk_group_rating_breakdown(request.user, [loc.pk for loc in loc_list])
    features = []
    for loc in loc_list:
        rating = loc.user_avg_rating if loc.user_avg_rating is not None else loc.overall_rating
        first_photo = next(iter(loc.photos.all()), None)
        features.append({
            "type": "Feature",
            "geometry": {
                "type": "Point",
                "coordinates": [float(loc.longitude), float(loc.latitude)],
            },
            "properties": {
                "id": loc.pk,
                "name": loc.name,
                "rating": str(round(rating, 1)) if rating else None,
                "review_count": loc.num_reviews,
                "group_rating_summary": _group_rating_summary_text(group_breakdowns.get(loc.pk)),
                "google_place_id": loc.google_place_id,
                "gluten_free": loc.gluten_free,
                "mine": loc.mine,
                "photo": first_photo.image.url if first_photo else None,
                "address": loc.address,
                "city": loc.city,
                "state": loc.state,
                "city_state": ", ".join(filter(None, [loc.city, loc.state])),
                "url": "/locations/{}/".format(loc.pk),
            },
        })
    return JsonResponse({"type": "FeatureCollection", "features": features})


# ── Items (HTMX) ──────────────────────────────────────────────────────────────

def _item_queryset_for_location(location):
    """Items visible for this location — its own, or (if chain-linked, see
    ChainGroup) every item shared across the whole chain group."""
    if location.chain_group_id:
        return Item.objects.filter(location__chain_group_id=location.chain_group_id)
    return Item.objects.filter(location=location)


def _annotated_items(location):
    """Items with avg_rating and review_count annotations, reviews prefetched."""
    return (
        _item_queryset_for_location(location)
        .annotate(
            avg_rating=Avg("reviews__rating"),
            review_count=Count("reviews", distinct=True),
            latest_review=Max("reviews__created_at"),
        )
        .prefetch_related("reviews__user", "reviews__submitted_by")
        .order_by("name")
        .distinct()
    )


def _item_behalf_targets(request, location, items):
    """Per-item {item_pk: [User, ...]} the current user may add a dish review
    for: is a linked account and doesn't already have a review for that item."""
    result = {}
    if not (request.user.is_authenticated and items):
        return result
    fam_ids = linked_account_ids(request.user)
    if not fam_ids:
        return result
    item_pks = [it.pk for it in items]
    already = {}   # item_pk -> set(user_ids who reviewed it)
    for iid, uid in ItemReview.objects.filter(
        item_id__in=item_pks, user_id__in=fam_ids
    ).values_list("item_id", "user_id"):
        already.setdefault(iid, set()).add(uid)
    fam_users = list(User.objects.filter(pk__in=fam_ids).order_by("username"))
    for it in items:
        targets = [u for u in fam_users if u.pk not in already.get(it.pk, set())]
        if targets:
            result[it.pk] = targets
    return result


def _render_items_section(
    request, location,
    item_form=None, show_form=False,
    review_item_pk=None, review_form=None,
    edit_item_pk=None, edit_form=None,
):
    # Determine the logged-in user's existing reviews (item_pk → review)
    my_reviews = {}
    if request.user.is_authenticated:
        for rev in ItemReview.objects.filter(
            item__in=_item_queryset_for_location(location), user=request.user
        ).select_related("item"):
            my_reviews[rev.item_id] = rev

    items = list(_annotated_items(location))
    item_behalf_targets = _item_behalf_targets(request, location, items)

    return render(request, "tracker/partials/items_section.html", {
        "location": location,
        "items": items,
        "item_form": item_form or ItemForm(),
        "show_form": show_form,
        "review_item_pk": review_item_pk,
        "review_form": review_form or ItemReviewForm(),
        "my_reviews": my_reviews,
        "item_behalf_targets": item_behalf_targets,
        "edit_item_pk": edit_item_pk,
        "edit_form": edit_form,
        # Reviewing an item/dish requires having rated the waypoint overall first.
        "location_rated": (
            request.user.is_authenticated and location.reviews.filter(user=request.user).exists()
        ),
    })


@login_required
def item_add(request, pk):
    location = get_object_or_404(Location, pk=pk)
    if request.method == "POST":
        form = ItemForm(request.POST)
        if form.is_valid():
            name = form.cleaned_data["name"]
            # Chain-linked locations share one item list — reuse a same-named
            # (case-insensitive) item from anywhere in the group instead of
            # creating a duplicate.
            item = _item_queryset_for_location(location).filter(name__iexact=name).first()
            if not item:
                item = form.save(commit=False)
                item.location = location
                item.save()
                _log(request, AuditLog.ACTION_CREATE, item,
                     'Added item "{}" to "{}"'.format(item.name, location.name))
            # Optionally create/update the submitter's initial review — same
            # rule as item_review_upsert: requires having rated the waypoint
            # overall first (the item itself is still added either way).
            initial_rating = request.POST.get("initial_rating", "").strip()
            initial_notes  = request.POST.get("initial_notes", "").strip()
            initial_private_notes = request.POST.get("initial_private_notes", "").strip()
            if initial_rating and not location.reviews.filter(user=request.user).exists():
                messages.error(
                    request,
                    'Item added. Rate "{}" overall before your dish rating can be saved.'.format(location.name),
                )
                initial_rating = ""
            if initial_rating:
                try:
                    from decimal import Decimal
                    val = Decimal(initial_rating)
                    if Decimal("0.5") <= val <= 5:
                        rev, _created = ItemReview.objects.update_or_create(
                            item=item, user=request.user,
                            defaults={"rating": val, "notes": initial_notes,
                                      "private_notes": initial_private_notes},
                        )
                        _log(request, AuditLog.ACTION_CREATE, rev,
                             'Rated "{}" {}/5 in "{}"'.format(item.name, val, location.name))
                except Exception:
                    pass
            return _render_items_section(request, location)
        return _render_items_section(request, location, item_form=form, show_form=True)
    show = request.GET.get("show", "1") != "0"
    return _render_items_section(request, location, show_form=show)


@login_required
def item_edit(request, pk, item_pk):
    if not is_superuser_role(request.user):
        return HttpResponseForbidden("Only superusers/admins can edit items.")
    location = get_object_or_404(Location, pk=pk)
    item = get_object_or_404(_item_queryset_for_location(location), pk=item_pk)
    if request.method == "POST":
        old_name = item.name
        form = ItemForm(request.POST, instance=item)
        if form.is_valid():
            form.save()
            if old_name != item.name:
                _log(
                    request, AuditLog.ACTION_UPDATE, item,
                    'Updated item in "{}": name: "{}" -> "{}"'.format(location.name, old_name, item.name),
                )
            return _render_items_section(request, location)
        return _render_items_section(
            request, location, edit_item_pk=item.pk, edit_form=form,
        )

    if request.GET.get("cancel"):
        return _render_items_section(request, location)
    return _render_items_section(
        request, location, edit_item_pk=item.pk, edit_form=ItemForm(instance=item),
    )


@login_required
def item_review_upsert(request, pk, item_pk):
    """Create or update the logged-in user's review for one item."""
    location = get_object_or_404(Location, pk=pk)
    item = get_object_or_404(_item_queryset_for_location(location), pk=item_pk)
    existing = ItemReview.objects.filter(item=item, user=request.user).first()

    # Reviewing an item/dish requires having rated the waypoint overall first
    # (editing an existing item review is still always allowed).
    if not existing and not location.reviews.filter(user=request.user).exists():
        messages.error(
            request, 'Rate "{}" overall before reviewing its items/dishes.'.format(location.name),
        )
        return _render_items_section(request, location)

    if request.method == "POST":
        form = ItemReviewForm(request.POST, instance=existing)
        if form.is_valid():
            review = form.save(commit=False)
            review.item = item
            review.user = request.user
            review.save()
            action = AuditLog.ACTION_UPDATE if existing else AuditLog.ACTION_CREATE
            _log(request, action, review,
                 '{} review for "{}" in "{}": {}/5'.format(
                     "Updated" if existing else "Added",
                     item.name, location.name, review.rating))
            return _render_items_section(request, location)
        return _render_items_section(
            request, location,
            review_item_pk=item_pk, review_form=form,
        )

    # GET — show the review form (or cancel: just render the section without form)
    if request.GET.get("cancel"):
        return _render_items_section(request, location)
    form = ItemReviewForm(instance=existing)
    return _render_items_section(
        request, location,
        review_item_pk=item_pk, review_form=form,
    )


@login_required
@require_POST
def item_review_delete(request, pk, item_pk):
    """Delete the logged-in user's own review (user=request.user — never a
    linked account's, even one added on your behalf)."""
    location = get_object_or_404(Location, pk=pk)
    item = get_object_or_404(_item_queryset_for_location(location), pk=item_pk)
    review = get_object_or_404(ItemReview, item=item, user=request.user)
    reason = _require_reason(request)
    if not reason:
        return HttpResponseBadRequest("A reason is required to delete a review.")
    _log(request, AuditLog.ACTION_DELETE, review,
         'Deleted review for "{}" in "{}" — reason: {}'.format(item.name, location.name, reason))
    review.delete()
    return _render_items_section(request, location)


@login_required
@require_POST
def item_review_on_behalf(request, pk, item_pk):
    """Add a dish/item review for a linked account (add-only). Must not already
    have a review for this item — no waypoint review is required first."""
    location = get_object_or_404(Location, pk=pk)
    item = get_object_or_404(_item_queryset_for_location(location), pk=item_pk)
    try:
        subject_id = int(request.POST.get("subject") or 0)
    except (TypeError, ValueError):
        subject_id = 0
    if subject_id not in linked_account_ids(request.user):
        return HttpResponseForbidden("You can only add reviews for your linked accounts.")
    subject = get_object_or_404(User, pk=subject_id)
    if ItemReview.objects.filter(item=item, user=subject).exists():
        messages.error(request,
                       "{} already reviewed “{}” — only they can change it.".format(subject.username, item.name))
        return _render_items_section(request, location)
    form = ItemReviewForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Please choose a rating for {}.".format(subject.username))
        return _render_items_section(request, location)
    review = form.save(commit=False)
    review.item = item
    review.user = subject
    review.submitted_by = request.user
    review.subject_seen = False
    review.private_notes = ""      # never write "private" notes on someone else's behalf
    review.save()
    _log(request, AuditLog.ACTION_CREATE, review,
         'Added review for "{}" in "{}" on behalf of {}: {}/5'.format(
             item.name, location.name, subject.username, review.rating))
    messages.success(request, "Dish review added for {}.".format(subject.username))
    return _render_items_section(request, location)


@login_required
@require_POST
def item_delete(request, pk, item_pk):
    if not is_superuser_role(request.user):
        return HttpResponseForbidden("Only superusers/admins can delete items.")
    location = get_object_or_404(Location, pk=pk)
    item = get_object_or_404(_item_queryset_for_location(location), pk=item_pk)
    reason = _require_reason(request)
    if not reason:
        return HttpResponseBadRequest("A reason is required to delete an item.")
    _log(
        request,
        AuditLog.ACTION_DELETE,
        item,
        'Deleted item "{}" from "{}" — reason: {}'.format(item.name, location.name, reason),
    )
    item.delete()
    return _render_items_section(request, location)


# ── Photos (HTMX) ─────────────────────────────────────────────────────────────

def _render_photos_section(request, location, photo_form=None, show_form=False):
    return render(request, "tracker/partials/photos_section.html", {
        "location": location,
        "photo_form": photo_form or PhotoForm(location=location),
        "show_form": show_form,
    })


@login_required
def photo_add(request, pk):
    location = get_object_or_404(Location, pk=pk)
    if request.method == "POST":
        form = PhotoForm(request.POST, request.FILES, location=location)
        if form.is_valid():
            photo = form.save(commit=False)
            photo.location = location
            photo.uploaded_by = request.user
            photo.save()
            detail = 'Uploaded photo to "{}"'.format(location.name)
            if photo.item:
                detail += ' tagged as "{}"'.format(photo.item.name)
            if photo.caption:
                detail += ' with caption "{}"'.format(photo.caption)
            _log(request, AuditLog.ACTION_CREATE, photo, detail)
            return _render_photos_section(request, location)
        return _render_photos_section(request, location, photo_form=form, show_form=True)
    show = request.GET.get("show", "1") != "0"
    return _render_photos_section(request, location, show_form=show)


@login_required
@require_POST
def photo_delete(request, pk, photo_pk):
    location = get_object_or_404(Location, pk=pk)
    photo = get_object_or_404(Photo, pk=photo_pk, location=location)
    if not can_delete(request.user, photo.uploaded_by):
        return HttpResponseForbidden("Only the uploader, a superuser, or an admin can delete this photo.")
    reason = _require_reason(request)
    if not reason:
        return HttpResponseBadRequest("A reason is required to delete a photo.")
    detail = 'Deleted photo from "{}" — reason: {}'.format(location.name, reason)
    if photo.caption:
        detail += ' (caption: "{}")'.format(photo.caption)
    _log(request, AuditLog.ACTION_DELETE, photo, detail)
    if photo.image and photo.image.storage.exists(photo.image.name):
        photo.image.delete(save=False)
    photo.delete()
    return _render_photos_section(request, location)


@login_required
@require_POST
def photo_rotate(request, pk, photo_pk):
    """Rotate a photo 90° clockwise or counter-clockwise in place."""
    from PIL import Image, UnidentifiedImageError
    location = get_object_or_404(Location, pk=pk)
    photo = get_object_or_404(Photo, pk=photo_pk, location=location)
    # Rotating rewrites the stored file in place — treat it like editing the
    # asset: only the uploader or an elevated role may do it.
    if not can_delete(request.user, photo.uploaded_by):
        return HttpResponseForbidden("Only the uploader, a superuser, or an admin can rotate this photo.")
    direction = request.POST.get("direction", "cw")
    angle = -90 if direction == "cw" else 90  # PIL rotates CCW by default
    try:
        img = Image.open(photo.image.path)
        img.load()   # forces the decode now, inside our DecompressionBomb guard
        # expand=True ensures the canvas grows for portrait/landscape swaps
        rotated = img.rotate(angle, expand=True)
        fmt = img.format or "JPEG"
        if fmt == "JPEG":
            rotated.save(photo.image.path, format=fmt, quality=90)
        else:
            rotated.save(photo.image.path, format=fmt)
        _log(request, AuditLog.ACTION_UPDATE, photo,
             'Rotated photo {} {}° in "{}"'.format(photo.pk, abs(angle), location.name))
    except (FileNotFoundError, UnidentifiedImageError, Image.DecompressionBombError, OSError):
        pass
    return _render_photos_section(request, location)


# ── Server-side IP geolocation (fallback when browser denies location) ────────

_PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                     "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                     "172.30.", "172.31.", "192.168.")

@login_required
@ratelimit("geoip", 20, 60, json=True)
def geoip_view(request):
    ip = _get_ip(request) or ""
    is_private = ip in ("127.0.0.1", "::1") or any(ip.startswith(p) for p in _PRIVATE_PREFIXES)
    if is_private:
        return JsonResponse({"status": "private"})

    # Cache the result per IP so repeat locate attempts don't re-hit (and get
    # rate-limited by) the external service — they return the cached city.
    cache_key = f"geoip_result_{ip}"
    cached = cache.get(cache_key)
    if cached:
        return JsonResponse(cached)

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,lat,lon,city,regionName"
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read())
        if data.get("status") == "success":
            result = {
                "status": "ok",
                "lat": data["lat"],
                "lng": data["lon"],
                "city": data.get("city", ""),
                "region": data.get("regionName", ""),
            }
            cache.set(cache_key, result, 60 * 30)   # 30 minutes per IP
            return JsonResponse(result)
    except Exception:
        pass
    return JsonResponse({"status": "error"})


# ── OSM POI search (server-side proxy + 24-hour cache) ────────────────────────

_OSM_CACHE_TTL = timedelta(hours=24)
_OVERPASS_URL  = "https://overpass-api.de/api/interpreter"


def _round2(value):
    """Round a float to 2 dp as a Decimal (cache key)."""
    return Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


@login_required
@ratelimit("osm_hour", 200, 3600, json=True)
@ratelimit("osm_min", 20, 60, json=True)
def osm_search(request):
    """
    Proxy for Overpass API with a 24-hour server-side cache.

    GET params: q, lat, lng, radius (metres, default 8047)
    Returns JSON: { cached: bool, fetched_at: iso, results: [...] }
    Each result mirrors the Overpass element with an extra 'dist_km' field
    computed server-side.
    """
    query    = request.GET.get("q", "").strip()
    try:
        lat    = float(request.GET.get("lat", 0))
        lng    = float(request.GET.get("lng", 0))
        radius = int(request.GET.get("radius", 8047))
    except (ValueError, TypeError):
        return JsonResponse({"error": "invalid params"}, status=400)

    if not query:
        return JsonResponse({"error": "q required"}, status=400)

    # ── Cache lookup ─────────────────────────────────────────────────────────
    clat = _round2(lat)
    clng = _round2(lng)

    cached = OsmSearchCache.objects.filter(
        query=query.lower(),
        center_lat=clat,
        center_lng=clng,
        radius_m=radius,
        fetched_at__gte=timezone.now() - _OSM_CACHE_TTL,
    ).first()

    if cached:
        return JsonResponse({
            "cached": True,
            "fetched_at": cached.fetched_at.isoformat(),
            "results": cached.results,
        })

    # ── Fetch from Overpass ───────────────────────────────────────────────────
    # Strip chars that break Overpass regex syntax
    q = re.sub(r'[\\"\[\](){}*+?.^$|]', '', query)
    overpass_q = (
        f'[out:json][timeout:25];('
        f'node["name"~"{q}",i](around:{radius},{lat},{lng});'
        f'way["name"~"{q}",i](around:{radius},{lat},{lng});'
        f'relation["name"~"{q}",i](around:{radius},{lat},{lng});'
        f');out center 200;'
    )

    try:
        # Overpass expects a form-encoded body: data=<query>
        form_body = urllib.parse.urlencode({'data': overpass_q}).encode()
        req = urllib.request.Request(
            _OVERPASS_URL,
            data=form_body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = json.loads(resp.read())
    except Exception as exc:
        return JsonResponse({"error": f"overpass unavailable: {exc}"}, status=502)

    # ── Compute distance + filter out no-coord elements ──────────────────────
    def _haversine(lat1, lon1, lat2, lon2):
        R = 6371.0
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)
        a = math.sin(dlat/2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon/2)**2
        return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    results = []
    for el in raw.get("elements", []):
        elat = el.get("lat") or (el.get("center") or {}).get("lat")
        elng = el.get("lon") or (el.get("center") or {}).get("lon")
        if elat is None or elng is None:
            continue
        el["dist_km"] = round(_haversine(lat, lng, elat, elng), 4)
        results.append(el)

    results.sort(key=lambda e: e["dist_km"])

    # ── Store / update cache ──────────────────────────────────────────────────
    OsmSearchCache.objects.update_or_create(
        query=query.lower(),
        center_lat=clat,
        center_lng=clng,
        radius_m=radius,
        defaults={"results": results, "fetched_at": timezone.now()},
    )

    return JsonResponse({
        "cached": False,
        "fetched_at": timezone.now().isoformat(),
        "results": results,
    })


# ── Location reviews (HTMX) ───────────────────────────────────────────────────

def _location_linked_targets(request, location):
    """Linked accounts the current user may add a review for HERE — i.e. is
    connected to, minus anyone who already has a review for this location
    (adding is allowed, editing another member's review is not)."""
    if not request.user.is_authenticated:
        return []
    fam_ids = linked_account_ids(request.user)
    if not fam_ids:
        return []
    reviewed = set(location.reviews.filter(user_id__in=fam_ids).values_list("user_id", flat=True))
    return list(User.objects.filter(pk__in=[i for i in fam_ids if i not in reviewed]).order_by("username"))


def _render_location_reviews(request, location, review_form=None, show_form=False):
    my_review = location.reviews.filter(user=request.user).first() \
        if request.user.is_authenticated else None
    return render(request, "tracker/partials/location_reviews.html", {
        "location": location,
        "my_review": my_review,
        "review_form": review_form or LocationReviewForm(instance=my_review),
        "show_form": show_form,
        "linked_targets": _location_linked_targets(request, location),
        # This view is only ever hit via HTMX, so it's safe to always include
        # the out-of-band header-badge swap (see template comment).
        "oob": True,
    })


@login_required
def location_review_upsert(request, pk):
    """Create or update the logged-in user's overall review for a location."""
    location = get_object_or_404(Location, pk=pk)
    existing = LocationReview.objects.filter(location=location, user=request.user).first()

    if request.method == "POST":
        form = LocationReviewForm(request.POST, instance=existing)
        if form.is_valid():
            review = form.save(commit=False)
            review.location = location
            review.user = request.user
            review.save()
            action = AuditLog.ACTION_UPDATE if existing else AuditLog.ACTION_CREATE
            _log(request, action, review,
                 '{} review for "{}": {}/5'.format(
                     "Updated" if existing else "Added", location.name, review.rating))
            return _render_location_reviews(request, location)
        return _render_location_reviews(request, location, review_form=form, show_form=True)

    if request.GET.get("cancel"):
        return _render_location_reviews(request, location)
    return _render_location_reviews(request, location, show_form=True)


@login_required
@require_POST
def location_review_delete(request, pk):
    location = get_object_or_404(Location, pk=pk)
    # user=request.user ensures you can only delete your OWN review — never a
    # linked account's, even one they added on your behalf belongs to you.
    review = get_object_or_404(LocationReview, location=location, user=request.user)
    reason = _require_reason(request)
    if not reason:
        return HttpResponseBadRequest("A reason is required to delete a review.")
    _log(request, AuditLog.ACTION_DELETE, review,
         'Deleted review for "{}" — reason: {}'.format(location.name, reason))
    review.delete()
    return _render_location_reviews(request, location)


@login_required
@require_POST
def location_review_on_behalf(request, pk):
    """Add a waypoint review for a linked account. Add-only: if the subject
    already has a review here it's left untouched (you can't edit theirs)."""
    location = get_object_or_404(Location, pk=pk)
    try:
        subject_id = int(request.POST.get("subject") or 0)
    except (TypeError, ValueError):
        subject_id = 0
    if subject_id not in linked_account_ids(request.user):
        return HttpResponseForbidden("You can only add reviews for your linked accounts.")
    subject = get_object_or_404(User, pk=subject_id)
    if LocationReview.objects.filter(location=location, user=subject).exists():
        messages.error(request,
                       "{} already has a review here — only they can change it.".format(subject.username))
        return _render_location_reviews(request, location)
    form = LocationReviewForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Please choose a rating for {}.".format(subject.username))
        return _render_location_reviews(request, location)
    review = form.save(commit=False)
    review.location = location
    review.user = subject
    review.submitted_by = request.user
    review.subject_seen = False       # surfaced to the subject on their next login
    review.save()
    _log(request, AuditLog.ACTION_CREATE, review,
         'Added review for "{}" on behalf of {}: {}/5'.format(location.name, subject.username, review.rating))
    messages.success(request, "Review added for {}.".format(subject.username))
    return _render_location_reviews(request, location)


# ── Collections ───────────────────────────────────────────────────────────────
# Collections are private to their owner by default (only the owner can see,
# edit, or delete their own collections list here) — an owner can flip a
# collection's is_public flag to surface it, read-only, on their profile page.

@login_required
def collection_list(request):
    collections = (
        Collection.objects
        .filter(created_by=request.user)
        .prefetch_related("locations")
        .annotate(loc_count=Count("locations"))
    )
    form = CollectionForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        coll = form.save(commit=False)
        coll.created_by = request.user
        if Collection.objects.filter(created_by=request.user, name=coll.name).exists():
            form.add_error("name", "You already have a collection with this name.")
        else:
            coll.save()
            _log(request, AuditLog.ACTION_CREATE, coll,
                 'Created collection "{}"'.format(coll.name))
            messages.success(request, 'Collection "{}" created.'.format(coll.name))
            return redirect("collection_list")
    return render(request, "tracker/collection_list.html", {
        "collections": collections,
        "form": form,
    })


@login_required
def collection_edit(request, pk):
    """Rename/redescribe a collection. Owner, superuser, or admin — matches
    the same override pattern used for waypoints (can_edit_location)."""
    coll = get_object_or_404(Collection, pk=pk)
    if not (coll.created_by_id == request.user.pk or is_superuser_role(request.user)):
        return HttpResponseForbidden("Only the owner, a superuser, or an admin can edit this collection.")
    if request.method == "POST":
        form = CollectionEditForm(request.POST, instance=coll)
        if form.is_valid():
            name = form.cleaned_data["name"]
            # Uniqueness is per-owner (see Collection.unique_together) — check
            # against the OWNER's other collections, not the editor's, since a
            # superuser editing someone else's collection isn't the owner.
            if Collection.objects.filter(created_by_id=coll.created_by_id, name=name).exclude(pk=coll.pk).exists():
                form.add_error("name", "A collection with that name already exists.")
            else:
                old_name = coll.name
                form.save()
                _log(request, AuditLog.ACTION_UPDATE, coll,
                     'Renamed collection "{}" to "{}"'.format(old_name, coll.name)
                     if old_name != coll.name else 'Updated collection "{}"'.format(coll.name))
                messages.success(request, 'Collection "{}" updated.'.format(coll.name))
                return redirect("collection_list")
        messages.error(request, form.errors.get("name", ["Couldn't save — check the form."])[0])
    return redirect("collection_list")


@login_required
@require_POST
def collection_delete(request, pk):
    coll = get_object_or_404(Collection, pk=pk, created_by=request.user)
    reason = (request.POST.get("reason") or "").strip()
    if not reason:
        messages.error(request, "Please provide a reason for deleting this collection.")
        return redirect("collection_list")
    _log(request, AuditLog.ACTION_DELETE, coll,
         'Deleted collection "{}" — reason: {}'.format(coll.name, reason))
    coll.delete()
    messages.success(request, "Collection deleted.")
    return redirect("collection_list")


@login_required
@require_POST
def collection_toggle_public(request, pk):
    coll = get_object_or_404(Collection, pk=pk, created_by=request.user)
    coll.is_public = not coll.is_public
    coll.save(update_fields=["is_public"])
    _log(request, AuditLog.ACTION_UPDATE, coll,
         'Made collection "{}" {}'.format(coll.name, "public" if coll.is_public else "private"))
    messages.success(request, 'Collection "{}" is now {}.'.format(
        coll.name, "public" if coll.is_public else "private"))
    return redirect("collection_list")


@login_required
@require_POST
def collection_toggle_featured(request, pk):
    """Superuser/admin only: feature/unfeature a PUBLIC collection. Featuring
    is independent of ownership — any superuser/admin can feature any public
    collection, not just their own."""
    if not is_superuser_role(request.user):
        return HttpResponseForbidden("Only superusers/admins can feature a collection.")
    coll = get_object_or_404(Collection, pk=pk, is_public=True)
    coll.is_featured = not coll.is_featured
    coll.save(update_fields=["is_featured"])
    _log(request, AuditLog.ACTION_UPDATE, coll,
         '{} collection "{}"'.format("Featured" if coll.is_featured else "Unfeatured", coll.name))
    messages.success(request, 'Collection "{}" is now {}.'.format(
        coll.name, "featured" if coll.is_featured else "unfeatured"))
    return redirect("collection_list")


@login_required
def collection_detail(request, pk):
    """Read-only view of a collection's waypoints, reachable by anyone once
    it's public — most commonly via the "Featured in" link superuser/admins
    surface on each member waypoint's own detail page."""
    coll = get_object_or_404(Collection.objects.select_related("created_by"), pk=pk)
    if not (coll.is_public or coll.created_by_id == request.user.pk):
        return HttpResponseForbidden("This collection is private.")
    locations = (
        coll.locations
        .annotate(user_avg_rating=Avg("reviews__rating"))
        .order_by("name")
    )
    return render(request, "tracker/collection_detail.html", {
        "collection": coll,
        "locations": locations,
    })


@login_required
@require_POST
def collection_toggle(request, pk, loc_pk):
    """Add/remove a location to/from one of the current user's own collections
    (HTMX, from the location detail page). Only the owner may edit it."""
    coll = get_object_or_404(Collection, pk=pk, created_by=request.user)
    location = get_object_or_404(Location, pk=loc_pk)
    if coll.locations.filter(pk=location.pk).exists():
        coll.locations.remove(location)
        detail = 'Removed "{}" from collection "{}"'.format(location.name, coll.name)
    else:
        coll.locations.add(location)
        detail = 'Added "{}" to collection "{}"'.format(location.name, coll.name)
    _log(request, AuditLog.ACTION_UPDATE, coll, detail)
    return render(request, "tracker/partials/collections_widget.html", {
        "location": location,
        "all_collections": Collection.objects.filter(created_by=request.user),
    })


@login_required
def user_profile(request, username):
    """A user's public profile: username, join year, and their public
    collections (alphabetical), each listing its waypoints alphabetically."""
    profile_user = get_object_or_404(User, username__iexact=username)
    collections = (
        Collection.objects
        .filter(created_by=profile_user, is_public=True)
        .prefetch_related("locations")
    )
    return render(request, "tracker/user_profile.html", {
        "profile_user": profile_user,
        "collections": collections,
    })


# ── Friend groups ────────────────────────────────────────────────────────────
# Private, invite-only groups. There is no public directory or search — the
# only way in is a member sharing the group's invite link (a random token,
# not the group name), and even then a requester sees only the group's name
# and member count until an existing member approves their join request.

def _is_group_member(user, group):
    return group.memberships.filter(user=user).exists()


@login_required
def group_list(request):
    """The current user's own groups only."""
    groups = FriendGroup.objects.filter(memberships__user=request.user).order_by("name")
    if request.method == "POST":
        name = (request.POST.get("name") or "").strip()
        if not name:
            messages.error(request, "Please enter a group name.")
        else:
            group = FriendGroup.objects.create(name=name, created_by=request.user)
            FriendGroupMembership.objects.create(group=group, user=request.user)
            _log(request, AuditLog.ACTION_CREATE, group, 'Created group "{}"'.format(group.name))
            messages.success(request, 'Group "{}" created.'.format(group.name))
            return redirect("group_detail", pk=group.pk)
    return render(request, "tracker/group_list.html", {"groups": groups})


@login_required
def group_detail(request, pk):
    group = get_object_or_404(FriendGroup, pk=pk)
    if not _is_group_member(request.user, group):
        return HttpResponseForbidden("You're not a member of this group.")

    members = User.objects.filter(friend_group_memberships__group=group).order_by("username")
    pending_requests = list(
        group.join_requests.filter(status=FriendGroupJoinRequest.STATUS_PENDING).select_related("user")
    )

    member_ids = set(members.values_list("pk", flat=True))
    rated_location_ids = list(
        LocationReview.objects.filter(user_id__in=member_ids).values_list("location_id", flat=True).distinct()
    )
    locations = (
        Location.objects.filter(pk__in=rated_location_ids)
        .annotate(user_avg_rating=Avg("reviews__rating"))
        .order_by("name")
    )
    # Breakdown is always relative to the VIEWER's own group memberships (not
    # just this group), so it's consistent with what shows on the waypoint
    # detail page and never depends on which group's page you're looking at.
    group_breakdowns = _bulk_group_rating_breakdown(request.user, rated_location_ids)
    waypoints = [
        {
            "location": loc,
            "system_rating": round(float(loc.user_avg_rating if loc.user_avg_rating is not None else loc.overall_rating), 1)
                if (loc.user_avg_rating is not None or loc.overall_rating) else None,
            "breakdown": group_breakdowns.get(loc.pk, []),
        }
        for loc in locations
    ]

    invite_url = request.build_absolute_uri(reverse("group_invite_preview", args=[group.invite_token]))

    return render(request, "tracker/group_detail.html", {
        "group": group,
        "members": members,
        "pending_requests": pending_requests,
        "waypoints": waypoints,
        "invite_url": invite_url,
    })


@login_required
def group_invite_preview(request, token):
    """What a non-member sees from an invite link: name + member count only."""
    group = get_object_or_404(FriendGroup, invite_token=token)
    if _is_group_member(request.user, group):
        return redirect("group_detail", pk=group.pk)
    existing = FriendGroupJoinRequest.objects.filter(group=group, user=request.user).first()

    if request.method == "POST":
        if existing and existing.status == FriendGroupJoinRequest.STATUS_PENDING:
            pass  # already pending — no-op
        elif existing:
            existing.status = FriendGroupJoinRequest.STATUS_PENDING
            existing.decided_at = None
            existing.decided_by = None
            existing.save(update_fields=["status", "decided_at", "decided_by"])
        else:
            existing = FriendGroupJoinRequest.objects.create(group=group, user=request.user)
        _log(request, AuditLog.ACTION_CREATE, existing,
             'Requested to join group "{}"'.format(group.name))
        messages.success(request, "Request sent — a member of the group needs to approve it.")
        return redirect("group_invite_preview", token=token)

    return render(request, "tracker/group_invite_preview.html", {
        "group": group,
        "existing_request": existing,
    })


def _group_request_decide(request, pk, request_pk, approve):
    group = get_object_or_404(FriendGroup, pk=pk)
    if not _is_group_member(request.user, group):
        return HttpResponseForbidden("Only group members can decide on join requests.")
    join_req = get_object_or_404(
        FriendGroupJoinRequest, pk=request_pk, group=group,
        status=FriendGroupJoinRequest.STATUS_PENDING,
    )
    join_req.status = FriendGroupJoinRequest.STATUS_APPROVED if approve else FriendGroupJoinRequest.STATUS_DENIED
    join_req.decided_at = timezone.now()
    join_req.decided_by = request.user
    join_req.save(update_fields=["status", "decided_at", "decided_by"])
    if approve:
        FriendGroupMembership.objects.get_or_create(group=group, user=join_req.user)
        _log(request, AuditLog.ACTION_UPDATE, group,
             'Approved "{}" to join group "{}"'.format(join_req.user.username, group.name))
        messages.success(request, "{} added to the group.".format(join_req.user.username))
    else:
        _log(request, AuditLog.ACTION_UPDATE, group,
             'Denied "{}" for group "{}"'.format(join_req.user.username, group.name))
        messages.success(request, "Request denied.")
    return redirect("group_detail", pk=group.pk)


@login_required
@require_POST
def group_request_approve(request, pk, request_pk):
    return _group_request_decide(request, pk, request_pk, approve=True)


@login_required
@require_POST
def group_request_deny(request, pk, request_pk):
    return _group_request_decide(request, pk, request_pk, approve=False)


@login_required
@require_POST
def group_invite_regenerate(request, pk):
    group = get_object_or_404(FriendGroup, pk=pk)
    if not _is_group_member(request.user, group):
        return HttpResponseForbidden("Only group members can do that.")
    from .models import _invite_token
    group.invite_token = _invite_token()
    group.save(update_fields=["invite_token"])
    _log(request, AuditLog.ACTION_UPDATE, group,
         'Regenerated invite link for group "{}"'.format(group.name))
    messages.success(request, "Invite link regenerated — the old link no longer works.")
    return redirect("group_detail", pk=group.pk)


@login_required
@require_POST
def group_leave(request, pk):
    group = get_object_or_404(FriendGroup, pk=pk)
    membership = FriendGroupMembership.objects.filter(group=group, user=request.user).first()
    if not membership:
        return redirect("group_list")
    membership.delete()
    _log(request, AuditLog.ACTION_DELETE, group, 'Left group "{}"'.format(group.name))
    if not group.memberships.exists():
        group.delete()
        messages.success(request, "You left the group. It had no other members, so it was removed.")
    else:
        messages.success(request, "You left the group.")
    return redirect("group_list")


# ── Linked accounts (one-to-one connections — review on each other's behalf) ──
# "Linked accounts" are a friends-list of direct, symmetric one-to-one links, NOT
# a group: being connected to B and to C never links B and C. Only directly
# connected users may post reviews on each other's behalf.

def linked_account_ids(user):
    """User ids DIRECTLY connected to `user` — exactly the people `user` may
    post reviews on behalf of (and who may post on `user`'s behalf). Not
    transitive: only first-degree connections."""
    lows = Connection.objects.filter(user_low=user).values_list("user_high_id", flat=True)
    highs = Connection.objects.filter(user_high=user).values_list("user_low_id", flat=True)
    return set(lows) | set(highs)


def _my_connect_token(user):
    token, _ = ConnectToken.objects.get_or_create(user=user)
    return token


@login_required
def linked_accounts(request):
    """The user's personal invite link + the list of people they're connected
    to one-to-one."""
    connected = list(User.objects.filter(pk__in=linked_account_ids(request.user)).order_by("username"))
    token = _my_connect_token(request.user)
    invite_url = request.build_absolute_uri(reverse("linked_account_connect", args=[token.token]))
    return render(request, "tracker/linked_accounts.html", {
        "connected": connected,
        "invite_url": invite_url,
    })


@login_required
def linked_account_connect(request, token):
    """Someone opened another user's personal invite link. Their own click on
    Approve creates the one-to-one connection between the two of them."""
    ct = get_object_or_404(ConnectToken.objects.select_related("user"), token=token)
    target = ct.user
    if target == request.user:
        messages.info(request, "That's your own invite link — share it with someone else.")
        return redirect("linked_accounts")
    already = target.pk in linked_account_ids(request.user)
    if request.method == "POST" and not already:
        low, high = Connection.ordered(request.user, target)
        Connection.objects.get_or_create(user_low=low, user_high=high)
        _log(request, AuditLog.ACTION_CREATE, request.user,
             'Linked account: connected with {}'.format(target.username))
        messages.success(request, "You're now connected with {}.".format(target.username))
        return redirect("linked_accounts")
    if already:
        messages.info(request, "You're already connected with {}.".format(target.username))
        return redirect("linked_accounts")
    return render(request, "tracker/linked_account_connect.html", {"target": target})


@login_required
@require_POST
def linked_account_invite_regenerate(request):
    """Rotate your personal invite link, invalidating the old one."""
    from .models import _invite_token
    token = _my_connect_token(request.user)
    token.token = _invite_token()
    token.save(update_fields=["token"])
    _log(request, AuditLog.ACTION_UPDATE, request.user, "Regenerated linked-account invite link")
    messages.success(request, "Invite link regenerated — the old link no longer works.")
    return redirect("linked_accounts")


@login_required
@require_POST
def linked_account_disconnect(request, user_pk):
    """Remove a one-to-one connection (either side can do this)."""
    other = get_object_or_404(User, pk=user_pk)
    low, high = Connection.ordered(request.user, other)
    Connection.objects.filter(user_low=low, user_high=high).delete()
    _log(request, AuditLog.ACTION_DELETE, request.user,
         'Linked account: disconnected from {}'.format(other.username))
    messages.success(request, "Removed {} from your linked accounts.".format(other.username))
    return redirect("linked_accounts")


@login_required
def on_behalf_reviews(request):
    """Everything linked accounts have logged on the current user's behalf,
    newest first. Viewing this page marks the as-yet-unseen ones seen (that's
    what the login banner points at)."""
    loc = list(
        LocationReview.objects.filter(user=request.user, submitted_by__isnull=False)
        .exclude(submitted_by=request.user)
        .select_related("location", "submitted_by").order_by("-created_at")
    )
    items = list(
        ItemReview.objects.filter(user=request.user, submitted_by__isnull=False)
        .exclude(submitted_by=request.user)
        .select_related("item", "item__location", "submitted_by").order_by("-created_at")
    )

    entries = []
    for r in loc:
        entries.append({
            "kind": "Waypoint", "title": r.location.name,
            "url": reverse("location_detail", args=[r.location_id]),
            "by": r.submitted_by, "rating": r.rating, "notes": r.notes,
            "when": r.created_at, "is_new": not r.subject_seen,
        })
    for r in items:
        entries.append({
            "kind": "Dish", "title": "{} · {}".format(r.item.name, r.item.location.name),
            "url": reverse("location_detail", args=[r.item.location_id]),
            "by": r.submitted_by, "rating": r.rating, "notes": r.notes,
            "when": r.created_at, "is_new": not r.subject_seen,
        })
    entries.sort(key=lambda e: e["when"], reverse=True)

    # Mark the unseen ones seen now that we've shown them.
    LocationReview.objects.filter(
        user=request.user, submitted_by__isnull=False, subject_seen=False
    ).exclude(submitted_by=request.user).update(subject_seen=True)
    ItemReview.objects.filter(
        user=request.user, submitted_by__isnull=False, subject_seen=False
    ).exclude(submitted_by=request.user).update(subject_seen=True)

    return render(request, "tracker/on_behalf_reviews.html", {"entries": entries})


# ── Export ────────────────────────────────────────────────────────────────────

@login_required
@ratelimit("export", 10, 3600)
def export_locations(request):
    """Download all waypoints as CSV, GeoJSON, or KML."""
    from django.http import HttpResponse
    import csv
    from xml.sax.saxutils import escape as xml_escape

    fmt = request.GET.get("format", "csv").lower()
    qs = Location.objects.annotate(user_avg_rating=Avg("reviews__rating")).order_by("name")

    if fmt == "geojson":
        features = []
        for loc in qs:
            if not loc.has_coords():
                continue
            features.append({
                "type": "Feature",
                "geometry": {"type": "Point",
                             "coordinates": [float(loc.longitude), float(loc.latitude)]},
                "properties": {
                    "name": loc.name,
                    "address": loc.address, "city": loc.city, "state": loc.state,
                    "gluten_free": loc.gluten_free, "dietary_notes": loc.dietary_notes,
                    "rating": float(loc.user_avg_rating or loc.overall_rating or 0) or None,
                    "public_notes": loc.public_notes,
                },
            })
        resp = JsonResponse({"type": "FeatureCollection", "features": features},
                            json_dumps_params={"indent": 2})
        resp["Content-Disposition"] = 'attachment; filename="waypoints.geojson"'
        return resp

    if fmt == "kml":
        placemarks = []
        for loc in qs:
            if not loc.has_coords():
                continue
            desc_parts = [p for p in [
                loc.address,
                f"GF: {loc.get_gluten_free_display()}" if loc.gluten_free else "",
                loc.public_notes,
            ] if p]
            placemarks.append(
                "<Placemark><name>{}</name><description>{}</description>"
                "<Point><coordinates>{},{},0</coordinates></Point></Placemark>".format(
                    xml_escape(loc.name),
                    xml_escape("\n".join(desc_parts)),
                    loc.longitude, loc.latitude,
                )
            )
        kml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<kml xmlns="http://www.opengis.net/kml/2.2"><Document>'
            '<name>Waypoints</name>{}</Document></kml>'.format("".join(placemarks))
        )
        resp = HttpResponse(kml, content_type="application/vnd.google-earth.kml+xml")
        resp["Content-Disposition"] = 'attachment; filename="waypoints.kml"'
        return resp

    # Default: CSV
    def _csv_safe(value):
        # Neutralise spreadsheet formula injection: a cell that a user made
        # start with =, +, -, @ (or tab/CR) can execute in Excel/Sheets.
        s = "" if value is None else str(value)
        if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
            return "'" + s
        return s

    resp = HttpResponse(content_type="text/csv")
    resp["Content-Disposition"] = 'attachment; filename="waypoints.csv"'
    writer = csv.writer(resp)
    writer.writerow([
        "name", "address", "city", "state",
        "latitude", "longitude",
        "gluten_free", "dietary_notes", "rating", "public_notes",
    ])
    for loc in qs:
        writer.writerow([_csv_safe(v) for v in [
            loc.name, loc.address, loc.city, loc.state,
            loc.latitude or "", loc.longitude or "",
            loc.gluten_free, loc.dietary_notes,
            loc.user_avg_rating or loc.overall_rating or "", loc.public_notes,
        ]])
    return resp


# ── Import (Google Takeout / GeoJSON) ─────────────────────────────────────────

def _parse_takeout_features(data):
    """
    Yield dicts of location fields from either a Google Takeout Saved Places
    JSON or a generic GeoJSON FeatureCollection.
    """
    for feat in data.get("features", []):
        geom = feat.get("geometry") or {}
        props = feat.get("properties") or {}
        coords = geom.get("coordinates") or [None, None]
        lng, lat = (coords + [None, None])[:2]

        # Google Takeout nests details under properties.location
        g_loc = props.get("location") or {}
        name = (
            g_loc.get("name")
            or props.get("name")
            or props.get("Title")
            or props.get("title")
            or ""
        ).strip()
        if not name:
            continue

        address = g_loc.get("address") or props.get("address") or ""
        yield {
            "name": name[:255],
            "address": address,
            "latitude": lat,
            "longitude": lng,
        }


@login_required
def import_locations(request):
    """Upload Google Takeout Saved Places JSON (or GeoJSON) to bulk-create waypoints."""
    form = TakeoutImportForm(request.POST or None, request.FILES or None)
    result = None
    if request.method == "POST" and form.is_valid():
        upload = form.cleaned_data["file"]
        data = None
        # Cap the upload so a huge file can't exhaust memory, and catch the
        # RecursionError/MemoryError a deeply-nested payload can raise (neither
        # is a ValueError, so they'd otherwise 500 the worker).
        MAX_IMPORT_BYTES = 10 * 1024 * 1024   # 10 MB
        if upload.size and upload.size > MAX_IMPORT_BYTES:
            form.add_error("file", "File is too large (max 10 MB).")
        else:
            try:
                data = json.loads(upload.read().decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                form.add_error("file", "Not a valid JSON file.")
            except (RecursionError, MemoryError):
                form.add_error("file", "That file is too large or too deeply nested to import.")

        if data is not None:
            created, skipped = 0, 0
            for fields in _parse_takeout_features(data):
                # Skip exact name duplicates (case-insensitive)
                if Location.objects.filter(name__iexact=fields["name"]).exists():
                    skipped += 1
                    continue
                loc = Location.objects.create(
                    created_by=request.user, **fields,
                )
                _log(request, AuditLog.ACTION_CREATE, loc,
                     'Imported "{}" from file upload'.format(loc.name))
                created += 1
            result = {"created": created, "skipped": skipped}
            if created:
                messages.success(
                    request,
                    "Imported {} waypoint{} ({} duplicate{} skipped).".format(
                        created, "s" if created != 1 else "",
                        skipped, "s" if skipped != 1 else ""),
                )
            else:
                messages.info(request, "No new waypoints found in that file.")
    return render(request, "tracker/import_export.html", {
        "form": form,
        "result": result,
    })


# ── Activity feed ─────────────────────────────────────────────────────────────

@login_required
def activity_feed(request):
    """The current user's own recent adds/updates/deletes."""
    logs = (
        AuditLog.objects
        .select_related("user")
        .filter(user=request.user)
        .filter(model_name__in=[
            "Location", "LocationReview", "ItemReview", "Item", "Photo",
        ])
        # Belt-and-suspenders for any older no-op update rows.
        .exclude(action=AuditLog.ACTION_UPDATE, detail__icontains="no changes")
        .order_by("-timestamp")[:100]
    )
    return render(request, "tracker/activity_feed.html", {"logs": logs})


# ── Duplicate detection API ───────────────────────────────────────────────────

@login_required
@ratelimit("check_dup", 60, 60, json=True)
def check_duplicate(request):
    """
    GET lat, lng[, exclude] → nearby existing waypoints within ~100 m,
    so the add form can warn before creating a duplicate.
    """
    try:
        lat = float(request.GET.get("lat"))
        lng = float(request.GET.get("lng"))
    except (TypeError, ValueError):
        return JsonResponse({"matches": []})
    exclude_pk = request.GET.get("exclude")

    # ~0.001° ≈ 111 m latitude; cheap bounding box first, then precise haversine
    box = 0.0015
    qs = Location.objects.filter(
        latitude__gte=lat - box, latitude__lte=lat + box,
        longitude__gte=lng - box, longitude__lte=lng + box,
    )
    if exclude_pk:
        qs = qs.exclude(pk=exclude_pk)

    def _haversine_m(lat1, lon1, lat2, lon2):
        R = 6371000.0
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)
        a = (math.sin(dlat / 2) ** 2
             + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2))
             * math.sin(dlon / 2) ** 2)
        return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    matches = []
    for loc in qs:
        dist = _haversine_m(lat, lng, float(loc.latitude), float(loc.longitude))
        if dist <= 100:
            matches.append({
                "id": loc.pk,
                "name": loc.name,
                "distance_m": round(dist),
                "url": "/locations/{}/".format(loc.pk),
            })
    matches.sort(key=lambda m: m["distance_m"])
    return JsonResponse({"matches": matches[:5]})


# ── robots.txt ─────────────────────────────────────────────────────────────────

def robots_txt(request):
    """Ask well-behaved crawlers to stay out entirely. Almost every page is
    behind login anyway (so nothing is indexable), but this makes the intent
    explicit for search engines and generic crawlers. Public by design."""
    from django.http import HttpResponse
    return HttpResponse("User-agent: *\nDisallow: /\n", content_type="text/plain")


# ── Admin dashboard ───────────────────────────────────────────────────────────

@user_passes_test(is_admin)
def admin_dashboard(request):
    """Staff-only management view. Admins can edit any waypoint here, including
    Google-sourced POIs whose name/address/pin are locked for regular users."""
    q = request.GET.get("q", "").strip()
    locations = Location.objects.select_related("created_by").order_by("name")
    if q:
        locations = locations.filter(
            Q(name__icontains=q) | Q(address__icontains=q)
            | Q(city__icontains=q) | Q(state__icontains=q)
        )
    return render(request, "tracker/admin_dashboard.html", {
        "locations": locations,
        "q": q,
        "location_count": Location.objects.count(),
        "user_count": User.objects.count(),
        "admin_count": User.objects.filter(is_staff=True).count(),
    })


@user_passes_test(is_admin)
def admin_users(request):
    """Admin-only user list. Admins can promote/demote admins and superusers here."""
    q = request.GET.get("q", "").strip()
    users = User.objects.annotate(
        is_superuser_role=Exists(
            User.groups.through.objects.filter(
                user_id=OuterRef("pk"), group__name=SUPERUSER_GROUP_NAME,
            )
        )
    ).order_by("-is_staff", "username")
    if q:
        users = users.filter(Q(username__icontains=q) | Q(email__icontains=q))
    return render(request, "tracker/admin_users.html", {
        "users": users,
        "q": q,
    })


@user_passes_test(is_admin)
@require_POST
def admin_user_toggle_admin(request, pk):
    target = get_object_or_404(User, pk=pk)

    if target.pk == request.user.pk:
        messages.error(request, "You can't change your own admin status.")
        return redirect("admin_users")

    if target.is_staff:
        # Guard against locking everyone out of the admin area.
        if User.objects.filter(is_staff=True).exclude(pk=target.pk).count() == 0:
            messages.error(request, "Can't remove the last remaining admin.")
            return redirect("admin_users")
        target.is_staff = False
        target.is_superuser = False
        target.save(update_fields=["is_staff", "is_superuser"])
        _log(request, AuditLog.ACTION_UPDATE, target,
             'Removed admin status from "{}"'.format(target.username))
        messages.success(request, "{} is no longer an admin.".format(target.username))
    else:
        target.is_staff = True
        target.is_superuser = True
        target.save(update_fields=["is_staff", "is_superuser"])
        _log(request, AuditLog.ACTION_UPDATE, target,
             'Made "{}" an admin'.format(target.username))
        messages.success(request, "{} is now an admin.".format(target.username))

    return redirect("admin_users")


@user_passes_test(is_admin)
@require_POST
def admin_user_toggle_superuser(request, pk):
    """Superuser is a plain auth Group membership — it grants content-editing
    abilities only, never Django admin site or infrastructure access."""
    target = get_object_or_404(User, pk=pk)
    group, _ = Group.objects.get_or_create(name=SUPERUSER_GROUP_NAME)

    if target.groups.filter(pk=group.pk).exists():
        target.groups.remove(group)
        _log(request, AuditLog.ACTION_UPDATE, target,
             'Removed superuser role from "{}"'.format(target.username))
        messages.success(request, "{} is no longer a superuser.".format(target.username))
    else:
        target.groups.add(group)
        _log(request, AuditLog.ACTION_UPDATE, target,
             'Made "{}" a superuser'.format(target.username))
        messages.success(request, "{} is now a superuser.".format(target.username))

    return redirect("admin_users")


# ── Admin: Google Maps usage & cost ───────────────────────────────────────────

@user_passes_test(is_admin)
def maps_usage(request):
    from . import gcp_usage

    if request.GET.get("refresh"):
        gcp_usage.clear_cache()
        return redirect("maps_usage")

    now = timezone.now()
    return render(request, "tracker/maps_usage.html", {
        "usage_configured": gcp_usage.usage_configured(),
        "cost_configured": gcp_usage.cost_configured(),
        "project_id": gcp_usage.project_id(),
        "billing_table": gcp_usage.billing_table(),
        "usage": gcp_usage.get_usage() if gcp_usage.usage_configured() else None,
        "cost": gcp_usage.get_cost() if gcp_usage.cost_configured() else None,
        "month_label": now.strftime("%B %Y"),
    })


# ── Admin audit log ───────────────────────────────────────────────────────────

@user_passes_test(is_admin)
def audit_log_view(request):
    logs = AuditLog.objects.select_related("user").all()
    q = request.GET.get("q", "").strip()
    action = request.GET.get("action", "")
    model = request.GET.get("model", "")
    if q:
        logs = logs.filter(
            Q(object_repr__icontains=q) | Q(detail__icontains=q) | Q(user__username__icontains=q)
        )
    if action:
        logs = logs.filter(action=action)
    if model:
        logs = logs.filter(model_name=model)
    model_names = (
        AuditLog.objects.values_list("model_name", flat=True).distinct().order_by("model_name")
    )
    return render(request, "tracker/audit_log.html", {
        "logs": logs[:500],
        "q": q,
        "action": action,
        "model": model,
        "action_choices": AuditLog.ACTION_CHOICES,
        "model_names": model_names,
    })
