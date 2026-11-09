import os
from decimal import Decimal

from django.contrib.auth.models import User
from django.core.validators import MaxValueValidator, MinValueValidator
from django.utils import timezone
from django.db import models


RATING_VALIDATORS = [
    MinValueValidator(Decimal("0.5")),
    MaxValueValidator(Decimal("5.0")),
]

MAX_PHOTO_PIXELS = 2_000_000  # 2 megapixels (downscale target)
MAX_IMAGE_PIXELS_CAP = 50_000_000  # reject-above cap (decompression-bomb guard)
MAX_PHOTO_UPLOAD_BYTES = 15 * 1024 * 1024  # 15 MB hard cap on the upload itself


class Location(models.Model):
    name = models.CharField(max_length=255)
    address = models.TextField(blank=True)
    city = models.CharField(max_length=100, blank=True)
    state = models.CharField(max_length=100, blank=True)
    latitude = models.DecimalField(max_digits=10, decimal_places=7, null=True, blank=True)
    longitude = models.DecimalField(max_digits=10, decimal_places=7, null=True, blank=True)
    google_place_id = models.CharField(
        max_length=255, blank=True, default="",
        help_text="Google Place ID — enables open-now refresh on the detail page",
    )
    public_notes = models.TextField(blank=True)
    private_notes = models.TextField(blank=True)

    GF_UNKNOWN   = ""
    GF_DEDICATED = "dedicated"
    GF_OPTIONS   = "options"
    GF_LIMITED   = "limited"
    GF_NONE      = "none"
    GF_CHOICES = [
        (GF_UNKNOWN,   "Unknown"),
        (GF_DEDICATED, "Dedicated GF kitchen (celiac-safe)"),
        (GF_OPTIONS,   "GF options available (shared kitchen)"),
        (GF_LIMITED,   "Limited GF (e.g. remove the bun)"),
        (GF_NONE,      "No gluten-free options"),
    ]
    gluten_free = models.CharField(
        max_length=20,
        choices=GF_CHOICES,
        blank=True,
        default="",
        help_text="Gluten-free accommodation level",
    )
    dietary_notes = models.TextField(
        blank=True,
        help_text="Dietary notes: allergies, cross-contamination info, etc.",
    )
    overall_rating = models.DecimalField(
        max_digits=2,
        decimal_places=1,
        null=True,
        blank=True,
        validators=RATING_VALIDATORS,
    )
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="locations"
    )
    chain_group = models.ForeignKey(
        "ChainGroup", on_delete=models.SET_NULL, null=True, blank=True, related_name="locations",
        help_text="Links this waypoint with other branches of the same chain "
                   "(e.g. every Burger King), sharing their items/dishes and item reviews.",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    def has_coords(self):
        return self.latitude is not None and self.longitude is not None

    @property
    def gf_agree_count(self):
        return self.gf_votes.filter(agrees=True).count()

    @property
    def gf_disagree_count(self):
        return self.gf_votes.filter(agrees=False).count()

    @property
    def avg_user_rating(self):
        """Average of per-user LocationReviews; falls back to legacy overall_rating."""
        agg = self.reviews.aggregate(avg=models.Avg("rating"))
        if agg["avg"] is not None:
            return round(agg["avg"], 1)
        return self.overall_rating

    @property
    def review_count(self):
        return self.reviews.count()


class ChainGroup(models.Model):
    """Links multiple physical Locations that are branches of the same
    chain/franchise — e.g. every Burger King — so their items/dishes and
    item reviews are shared across branches. Each location keeps its own
    address, hours, and location-level rating/reviews separate; only items
    (and their reviews) are pooled across the group."""

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        names = ", ".join(self.locations.order_by("name").values_list("name", flat=True)[:3])
        return "Chain: {}".format(names)


class Collection(models.Model):
    """A user-curated group of waypoints: a trip, a theme, a wishlist.

    Private by default and manageable only by its owner. An owner can flip
    is_public to surface it (read-only, to everyone) on their profile page.
    """

    name = models.CharField(max_length=120)
    description = models.TextField(blank=True)
    locations = models.ManyToManyField(Location, related_name="collections", blank=True)
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="collections"
    )
    is_public = models.BooleanField(
        default=False, help_text="Public collections appear on your profile page."
    )
    # Superuser/admin-only spotlight (owners can't set this themselves). Only
    # takes effect on an already-public collection: every waypoint in
    # `locations` then shows a link back to this collection's own detail page
    # (e.g. a company's "Food Trucks" collection, linked from every food
    # truck's own waypoint page).
    is_featured = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]
        unique_together = [("created_by", "name")]

    def __str__(self):
        return self.name


class LocationReview(models.Model):
    """One overall rating + review per registered user per location."""

    location = models.ForeignKey(Location, on_delete=models.CASCADE, related_name="reviews")
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="location_reviews")
    rating = models.DecimalField(
        max_digits=2,
        decimal_places=1,
        validators=RATING_VALIDATORS,
    )
    notes = models.TextField(blank=True, help_text="Your review of this place")
    # Who actually authored this review. NULL means the subject wrote it
    # themselves; a different user means a linked account posted it on the
    # subject's behalf (see Connection). The review always "belongs to" `user`
    # — only they (or an admin) may edit/delete it.
    submitted_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="+",
    )
    # False while the subject hasn't yet seen the "added on your behalf" notice.
    subject_seen = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("location", "user")]
        ordering = ["-created_at"]

    @property
    def on_behalf(self):
        return self.submitted_by_id is not None and self.submitted_by_id != self.user_id

    def __str__(self):
        return f"{self.user.username} → {self.location.name}: {self.rating}"


class GlutenFreeVote(models.Model):
    """A community up/down vote on whether a location's gluten-free status is
    accurate. One vote per user per location; re-voting the same way clears it."""

    location = models.ForeignKey(Location, on_delete=models.CASCADE, related_name="gf_votes")
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="gf_votes")
    agrees = models.BooleanField(help_text="True = agrees the GF status is accurate")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("location", "user")]

    def __str__(self):
        verb = "agrees" if self.agrees else "disagrees"
        return f"{self.user.username} {verb} on GF for {self.location.name}"


class Item(models.Model):
    location = models.ForeignKey(Location, on_delete=models.CASCADE, related_name="items")
    name = models.CharField(max_length=255)
    # General description/notes about the item — not a per-user rating
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return f"{self.location.name} – {self.name}"


class ItemReview(models.Model):
    """One rating + review per registered user per item/dish."""

    item = models.ForeignKey(Item, on_delete=models.CASCADE, related_name="reviews")
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="item_reviews")
    rating = models.DecimalField(
        max_digits=2,
        decimal_places=1,
        validators=RATING_VALIDATORS,
    )
    notes = models.TextField(blank=True, help_text="Your personal review or tasting notes")
    private_notes = models.TextField(
        blank=True, help_text="Only visible to you — never shown to other users"
    )
    # See LocationReview.submitted_by / subject_seen — same on-behalf mechanics.
    submitted_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="+",
    )
    subject_seen = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("item", "user")]
        ordering = ["-created_at"]

    @property
    def on_behalf(self):
        return self.submitted_by_id is not None and self.submitted_by_id != self.user_id

    def __str__(self):
        return f"{self.user.username} → {self.item.name}: {self.rating}"


def _photo_upload_path(instance, filename):
    ext = os.path.splitext(filename)[1].lower()
    return f"photos/location_{instance.location_id}/{instance.location_id}_{filename}"


class Photo(models.Model):
    location = models.ForeignKey(Location, on_delete=models.CASCADE, related_name="photos")
    item = models.ForeignKey(
        Item, on_delete=models.SET_NULL, null=True, blank=True, related_name="photos",
        help_text="Optionally tag this photo as a specific dish/item",
    )
    image = models.ImageField(upload_to=_photo_upload_path)
    caption = models.CharField(max_length=255, blank=True)
    uploaded_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="photos"
    )
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-uploaded_at"]

    def __str__(self):
        return f"Photo for {self.location.name} ({self.pk})"

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        self._strip_metadata_and_resize()

    def _strip_metadata_and_resize(self):
        from PIL import Image, ImageOps, UnidentifiedImageError
        # Bombs/oversize files are rejected up front in PhotoForm.clean_image,
        # so this is best-effort; keep the cap set as defence in depth and skip
        # (leaving the original — metadata included — on anything we can't
        # process, rather than risk mangling or losing the upload).
        Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS_CAP
        try:
            img = Image.open(self.image.path)
            fmt = img.format or "JPEG"   # must capture before transpose/resize — neither preserves it
            # Bake in any EXIF-only rotation (phones often store orientation
            # as a tag rather than rotating the actual pixels) BEFORE the
            # metadata that tag lives in gets stripped below — otherwise the
            # photo would come out sideways/upside-down once that's gone.
            img = ImageOps.exif_transpose(img)
            w, h = img.size
            if w * h > MAX_PHOTO_PIXELS:
                ratio = (MAX_PHOTO_PIXELS / (w * h)) ** 0.5
                new_size = (max(1, int(w * ratio)), max(1, int(h * ratio)))
                img = img.resize(new_size, Image.LANCZOS)
            # Re-encoding from the decoded pixel data alone, with no exif= or
            # icc_profile= passed to save(), is what actually drops EXIF/GPS/
            # ICC metadata — always do this, even when no resize was needed,
            # so a small upload doesn't keep its original metadata intact.
            if fmt == "JPEG":
                img.save(self.image.path, format=fmt, optimize=True, quality=85)
            else:
                img.save(self.image.path, format=fmt, optimize=True)
        except (FileNotFoundError, UnidentifiedImageError, Image.DecompressionBombError, OSError):
            return


class OsmSearchCache(models.Model):
    """
    Caches Overpass API search results for up to 24 hours.
    Key: (query, lat/lng rounded to 2 dp ≈ 1 km grid, radius_m).
    """
    query      = models.CharField(max_length=255, db_index=True)
    center_lat = models.DecimalField(max_digits=7, decimal_places=2)   # ~1 km grid
    center_lng = models.DecimalField(max_digits=8, decimal_places=2)
    radius_m   = models.IntegerField()
    results    = models.JSONField(default=list)   # list of serialised Overpass element dicts
    fetched_at = models.DateTimeField(default=timezone.now)  # updatable so cache can refresh

    class Meta:
        unique_together = [("query", "center_lat", "center_lng", "radius_m")]
        ordering = ["-fetched_at"]

    def __str__(self):
        return f'OSM "{self.query}" @({self.center_lat},{self.center_lng}) r={self.radius_m}m'


class AuditLog(models.Model):
    ACTION_CREATE = "create"
    ACTION_UPDATE = "update"
    ACTION_DELETE = "delete"
    ACTION_CHOICES = [
        (ACTION_CREATE, "Create"),
        (ACTION_UPDATE, "Update"),
        (ACTION_DELETE, "Delete"),
    ]

    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=10, choices=ACTION_CHOICES)
    model_name = models.CharField(max_length=50)
    object_id = models.PositiveIntegerField(null=True, blank=True)
    object_repr = models.CharField(max_length=255)
    detail = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        ordering = ["-timestamp"]

    def __str__(self):
        user_str = self.user.username if self.user else "anonymous"
        return f"{self.timestamp:%Y-%m-%d %H:%M} | {user_str} | {self.action} {self.model_name} #{self.object_id}"


class TermsAcceptance(models.Model):
    """Records that a user accepted a specific version of the Terms of Service.

    Bumping settings.TERMS_VERSION invalidates prior acceptances (no row exists
    for the new version), so every user is prompted to review and re-accept.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="terms_acceptances")
    version = models.CharField(max_length=40)
    accepted_at = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        unique_together = [("user", "version")]
        ordering = ["-accepted_at"]

    def __str__(self):
        return f"{self.user.username} accepted TOS {self.version} on {self.accepted_at:%Y-%m-%d}"


class EmailVerification(models.Model):
    """Tracks whether a user has confirmed their email address. Users must
    verify before they can use the app (enforced by middleware)."""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="email_verification")
    verified = models.BooleanField(default=False)
    verified_at = models.DateTimeField(null=True, blank=True)
    last_sent_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        state = "verified" if self.verified else "unverified"
        return f"{self.user.username}: {state}"


class TOTPDevice(models.Model):
    """A user's TOTP (authenticator-app) secret. `confirmed` becomes True once
    the user verifies a code during setup; 2FA is active only when confirmed.
    The secondary/backup MFA method — see WebAuthnCredential for the default
    one. Optional for regular users, required for admins (either method, or
    both, satisfies that requirement; they're alternatives, not additive)."""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="totp")
    secret = models.CharField(max_length=64)
    confirmed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username}: 2FA {'on' if self.confirmed else 'pending'}"


class WebAuthnCredential(models.Model):
    """A registered passkey. The default/primary MFA method — a user may
    register several (one per device/browser); any single one of them, same
    as a confirmed TOTPDevice, satisfies the account's MFA requirement."""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="webauthn_credentials")
    credential_id = models.BinaryField(unique=True)
    public_key = models.BinaryField()
    # WebAuthn's per-credential use counter — rising on every successful
    # assertion. Many platform authenticators (Face ID, Windows Hello, …)
    # never increment it and always report 0; verify_authentication_response
    # (see tracker.views) already accounts for that when checking it.
    sign_count = models.BigIntegerField(default=0)
    name = models.CharField(
        max_length=100, blank=True,
        help_text='Your label for this passkey, e.g. "iPhone" or "YubiKey"',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.user.username}: passkey {self.name or self.pk}"


class PendingRegistration(models.Model):
    """A signup awaiting email confirmation. No User account exists until the
    emailed link is clicked, so an unverified email can never register."""
    username = models.CharField(max_length=150)
    email = models.EmailField()
    password = models.CharField(max_length=128)   # already hashed
    token = models.CharField(max_length=64, unique=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"pending {self.username} <{self.email}>"


def _invite_token():
    import secrets
    return secrets.token_urlsafe(24)


class FriendGroup(models.Model):
    """A private friend group. Not publicly listed or searchable — the only
    way in is a member sharing the group's invite link, and even then a
    requester sees just the name and member count until an existing member
    approves their join request."""
    name = models.CharField(max_length=120)
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    # The invite link's random ID — deliberately not derived from the group
    # name so the URL alone reveals nothing. Any member can rotate it
    # (invalidating the old link) via group_invite_regenerate.
    invite_token = models.CharField(max_length=64, unique=True, default=_invite_token)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    @property
    def member_count(self):
        return self.memberships.count()


class FriendGroupMembership(models.Model):
    group = models.ForeignKey(FriendGroup, on_delete=models.CASCADE, related_name="memberships")
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="friend_group_memberships")
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [("group", "user")]

    def __str__(self):
        return f"{self.user.username} in {self.group.name}"


class FriendGroupJoinRequest(models.Model):
    STATUS_PENDING  = "pending"
    STATUS_APPROVED = "approved"
    STATUS_DENIED   = "denied"
    STATUS_CHOICES = [
        (STATUS_PENDING,  "Pending"),
        (STATUS_APPROVED, "Approved"),
        (STATUS_DENIED,   "Denied"),
    ]

    group = models.ForeignKey(FriendGroup, on_delete=models.CASCADE, related_name="join_requests")
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="friend_group_join_requests")
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=STATUS_PENDING)
    requested_at = models.DateTimeField(auto_now_add=True)
    decided_at = models.DateTimeField(null=True, blank=True)
    decided_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )

    class Meta:
        unique_together = [("group", "user")]
        ordering = ["-requested_at"]

    def __str__(self):
        return f"{self.user.username} -> {self.group.name} ({self.status})"


class ConnectToken(models.Model):
    """A user's personal invite link for linked accounts. Sharing the URL lets
    someone open it and connect one-to-one with this user. Regenerating the
    token invalidates the old link."""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="connect_token")
    token = models.CharField(max_length=64, unique=True, default=_invite_token)

    def __str__(self):
        return f"connect-token for {self.user.username}"


class Connection(models.Model):
    """A symmetric one-to-one "linked account" between two users — a
    friends-list style connection, NOT a group. Being linked to B and to C does
    not link B and C in any way. Either linked user may post waypoint/dish
    reviews on the other's behalf; only the attributed user (or an admin) can
    edit/delete them. Stored as an ordered pair (user_low.pk < user_high.pk) so
    each pair is unique regardless of who initiated it."""
    user_low = models.ForeignKey(User, on_delete=models.CASCADE, related_name="+")
    user_high = models.ForeignKey(User, on_delete=models.CASCADE, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [("user_low", "user_high")]

    def __str__(self):
        return f"{self.user_low.username} ↔ {self.user_high.username}"

    @staticmethod
    def ordered(a, b):
        """Return (low, high) ordered by pk for canonical storage."""
        return (a, b) if a.pk < b.pk else (b, a)
