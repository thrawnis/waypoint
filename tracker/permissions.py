"""Role helpers shared by views and templates.

Two roles:
- Admin — Django's built-in is_staff (+ is_superuser). The ONLY role with
  access to the Django admin site (/admin/), the in-app admin dashboard,
  user management, audit log, and Maps usage/cost pages.
- Superuser — an app-level role (membership in the "Superuser" auth Group)
  that unlocks content-editing/deleting abilities formerly tied to is_staff
  (editing Google-sourced POI fields, item names, deleting others' content,
  etc.) WITHOUT any Django admin site or infrastructure access. Deliberately
  NOT implemented via is_staff/is_superuser, so it can never grant Django
  access. Admins implicitly have every Superuser ability too.
"""

SUPERUSER_GROUP_NAME = "Superuser"


def is_admin(user):
    return bool(user) and user.is_authenticated and user.is_staff


def is_superuser_role(user):
    if not user or not user.is_authenticated:
        return False
    return user.is_staff or user.groups.filter(name=SUPERUSER_GROUP_NAME).exists()


def user_has_mfa(user):
    """True if this user has at least one usable MFA method set up — a
    registered passkey (the default/primary method) or a confirmed TOTP
    device (the secondary/backup one). They're alternatives: either single
    one satisfies the account's MFA requirement, never both at once."""
    from .models import TOTPDevice, WebAuthnCredential
    return (
        WebAuthnCredential.objects.filter(user=user).exists()
        or TOTPDevice.objects.filter(user=user, confirmed=True).exists()
    )


def can_edit_location(user, location):
    """Editing an existing waypoint's content (and structural actions like
    chain link/unlink) is limited to its creator or an elevated role —
    mirroring can_delete, so arbitrary users can't overwrite/merge others'
    waypoints."""
    if not user or not user.is_authenticated:
        return False
    return is_superuser_role(user) or (location.created_by_id == user.pk)
