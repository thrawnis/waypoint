import re

from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

from .models import (
    Collection, Item, ItemReview, Location, LocationReview, Photo,
    MAX_IMAGE_PIXELS_CAP, MAX_PHOTO_UPLOAD_BYTES,
)


# A run of letters (Unicode-aware, so accented letters like "ñ" stay part of
# the same word instead of starting a new one) with embedded apostrophes
# glued on, e.g. "mcdonald's" or "jalapeño" each match as a single run.
_WORD_RUN_RE = re.compile(r"(?:[^\W\d_]|')+")


def normalize_case(text):
    """Title-case a value only if the user typed it in ALL CAPS or all lowercase
    (i.e. not intentional casing). Mixed-case values are returned untouched."""
    if not text:
        return text
    s = text.strip()
    if not any(c.isalpha() for c in s):
        return s
    if s == s.upper() or s == s.lower():
        return _WORD_RUN_RE.sub(lambda m: m.group(0).capitalize(), s)
    return s


# Small connector words that stay lowercase in title case, unless they're the
# first or last word (standard title-casing convention).
_TITLE_CASE_SMALL_WORDS = {
    "a", "an", "and", "as", "at", "but", "by", "en", "for", "if", "in",
    "nor", "of", "on", "or", "per", "the", "to", "v", "vs", "via",
}


def to_title_case(text):
    """Always apply proper title case, regardless of how it was typed —
    unlike normalize_case, which only fixes SHOUTING or all-lowercase.
    Small connector words (and, of, the, ...) stay lowercase unless first
    or last. Apostrophes are handled so "mcdonald's" -> "Mcdonald's"."""
    if not text:
        return text
    s = text.strip()
    if not any(c.isalpha() for c in s):
        return s

    tokens = re.split(r'(\s+)', s)
    word_positions = [i for i, t in enumerate(tokens) if t.strip()]
    if not word_positions:
        return s

    def cap(match):
        word = match.group(0)
        return word[0].upper() + word[1:].lower()

    out = []
    for i, tok in enumerate(tokens):
        if not tok.strip():
            out.append(tok)
            continue
        capped = _WORD_RUN_RE.sub(cap, tok)
        bare = re.sub(r"[^A-Za-z]", "", tok).lower()
        is_edge = i == word_positions[0] or i == word_positions[-1]
        if not is_edge and bare in _TITLE_CASE_SMALL_WORDS:
            capped = capped.lower()
        out.append(capped)
    return "".join(out)


class RegisterForm(UserCreationForm):
    email = forms.EmailField(required=True, help_text="You'll need to verify this address.")
    agree_terms = forms.BooleanField(
        required=True,
        error_messages={"required": "You must agree to the Terms of Service to register."},
    )
    captcha = forms.CharField(
        required=True, max_length=16, label="Enter the characters shown",
        widget=forms.TextInput(attrs={
            "autocomplete": "off", "autocapitalize": "characters", "spellcheck": "false",
            "placeholder": "Type the code above",
        }),
    )

    class Meta:
        model = User
        fields = ("username", "email", "password1", "password2")

    def __init__(self, *args, request=None, **kwargs):
        # Needs the request to check the answer stashed in the session by the
        # captcha image view.
        self.request = request
        super().__init__(*args, **kwargs)

    def clean_captcha(self):
        from time import time
        from .captcha import CAPTCHA_TTL, SESSION_ANSWER, SESSION_TIME
        answer = (self.cleaned_data.get("captcha") or "").strip().upper()
        session = getattr(self.request, "session", None)
        expected = session.get(SESSION_ANSWER) if session is not None else None
        issued = session.get(SESSION_TIME, 0) if session is not None else 0
        if not expected or (time() - issued) > CAPTCHA_TTL:
            raise forms.ValidationError("The verification code expired — please try the new one.")
        if answer != expected:
            raise forms.ValidationError("The verification code didn't match — please try again.")
        return answer

    def clean_username(self):
        # Usernames are case-insensitive at login, so reject one that only
        # differs in case from an existing account (which would make the login
        # lookup ambiguous). The default UserCreationForm only checks exact.
        username = self.cleaned_data.get("username", "")
        if username and User.objects.filter(username__iexact=username).exists():
            raise forms.ValidationError("A user with that username already exists.")
        return username

    def clean_email(self):
        email = self.cleaned_data.get("email", "").strip()
        if email and User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("An account with this email already exists.")
        return email


class LocationForm(forms.ModelForm):
    # Fields sourced from Google when a waypoint is saved from a map POI.
    # For such entries they are locked so only manually added waypoints are editable.
    GOOGLE_SOURCED_FIELDS = ["name", "address", "latitude", "longitude", "city", "state"]

    class Meta:
        model = Location
        fields = [
            "name",
            "address",
            "city",
            "state",
            "latitude",
            "longitude",
            "google_place_id",
            "gluten_free",
            "dietary_notes",
            "public_notes",
            "private_notes",
        ]
        widgets = {
            "name": forms.TextInput(attrs={"placeholder": "Location name"}),
            "address": forms.TextInput(attrs={"placeholder": "Address (optional — use map to set)"}),
            "city": forms.HiddenInput(),
            "state": forms.HiddenInput(),
            "latitude": forms.HiddenInput(),
            "longitude": forms.HiddenInput(),
            "google_place_id": forms.HiddenInput(),
            "dietary_notes": forms.Textarea(
                attrs={"rows": 3, "placeholder": "e.g. Dedicated GF fryer, staff trained on cross-contamination, ask for GF menu"}
            ),
            "public_notes": forms.Textarea(attrs={"rows": 4, "placeholder": "Visible to everyone"}),
            "private_notes": forms.Textarea(
                attrs={"rows": 4, "placeholder": "Only visible when logged in"}
            ),
        }

    def __init__(self, *args, unlock_google_fields=False, **kwargs):
        super().__init__(*args, **kwargs)
        # A Google Place ID (from a saved POI) marks the identity fields as
        # authoritative; lock them so they can't be edited after the fact.
        # Admins can pass unlock_google_fields=True to override the lock.
        pid = self.initial.get("google_place_id") or getattr(self.instance, "google_place_id", "")
        self.google_locked = bool(pid) and not unlock_google_fields
        if self.google_locked:
            for name in self.GOOGLE_SOURCED_FIELDS:
                field = self.fields.get(name)
                if field:
                    field.widget.attrs["readonly"] = True

    # Fix up shouting / all-lowercase entry on the identifying fields.
    def clean_name(self):
        return normalize_case(self.cleaned_data.get("name", ""))

    def clean_address(self):
        return normalize_case(self.cleaned_data.get("address", ""))

    def clean_city(self):
        return normalize_case(self.cleaned_data.get("city", ""))

    def clean_state(self):
        return normalize_case(self.cleaned_data.get("state", ""))

    def clean(self):
        """Ignore any tampered edits to locked, Google-sourced fields."""
        cleaned = super().clean()
        if getattr(self, "google_locked", False) and self.instance.pk:
            for name in self.GOOGLE_SOURCED_FIELDS:
                if name in cleaned:
                    cleaned[name] = getattr(self.instance, name)
        return cleaned


class ItemForm(forms.ModelForm):
    """Create/edit an item (dish/product). Rating lives in ItemReview."""

    class Meta:
        model = Item
        fields = ["name"]
        widgets = {
            "name": forms.TextInput(attrs={"placeholder": "Item or dish name"}),
        }

    def clean_name(self):
        # Dishes are always recorded in proper (title) case, regardless of
        # how the user typed it — unlike location names, which are only
        # fixed when SHOUTING or all-lowercase.
        return to_title_case(self.cleaned_data.get("name", ""))


class ItemReviewForm(forms.ModelForm):
    """A single user's rating + review text for one item."""

    class Meta:
        model = ItemReview
        fields = ["rating", "notes", "private_notes"]
        widgets = {
            "rating": forms.HiddenInput(),
            "notes": forms.Textarea(
                attrs={"rows": 2, "placeholder": "Your review (optional, visible to everyone)"}
            ),
            "private_notes": forms.Textarea(
                attrs={"rows": 2, "placeholder": "Private note (optional, only you can see this)"}
            ),
        }

    def clean_rating(self):
        rating = self.cleaned_data.get("rating")
        if not rating:
            raise forms.ValidationError("Please select a star rating.")
        return rating


class LocationReviewForm(forms.ModelForm):
    """A single user's overall rating + review for one location."""

    class Meta:
        model = LocationReview
        fields = ["rating", "notes"]
        widgets = {
            "rating": forms.HiddenInput(),
            "notes": forms.Textarea(
                attrs={"rows": 2, "placeholder": "Your review of this place (optional)"}
            ),
        }

    def clean_rating(self):
        rating = self.cleaned_data.get("rating")
        if not rating:
            raise forms.ValidationError("Please select a star rating.")
        return rating


class CollectionForm(forms.ModelForm):
    class Meta:
        model = Collection
        fields = ["name", "description", "is_public"]
        widgets = {
            "name": forms.TextInput(attrs={"placeholder": "e.g. Austin 2026, GF-safe spots"}),
            "description": forms.Textarea(attrs={"rows": 2, "placeholder": "Description (optional)"}),
        }


class CollectionEditForm(forms.ModelForm):
    """Rename/redescribe an existing collection. Deliberately excludes
    is_public (that has its own dedicated toggle button/action) so submitting
    this form can never silently flip it off."""

    class Meta:
        model = Collection
        fields = ["name", "description"]
        widgets = {
            "name": forms.TextInput(attrs={"placeholder": "e.g. Austin 2026, GF-safe spots"}),
            "description": forms.Textarea(attrs={"rows": 2, "placeholder": "Description (optional)"}),
        }


class TakeoutImportForm(forms.Form):
    """Upload a Google Takeout 'Saved Places' JSON or a generic GeoJSON file."""

    file = forms.FileField(
        help_text="Saved Places.json from Google Takeout, or any GeoJSON FeatureCollection",
    )


class PhotoForm(forms.ModelForm):
    class Meta:
        model = Photo
        fields = ["image", "item", "caption"]
        widgets = {
            "caption": forms.TextInput(attrs={"placeholder": "Caption (optional)"}),
        }

    def __init__(self, *args, location=None, **kwargs):
        super().__init__(*args, **kwargs)
        # Only this waypoint's own dishes are valid choices, and there's
        # nothing to tag at all on a waypoint with no items yet.
        qs = location.items.all() if location is not None else Item.objects.none()
        self.fields["item"].queryset = qs
        self.fields["item"].required = False
        self.fields["item"].empty_label = "No dish (general photo)"

    def clean_image(self):
        image = self.cleaned_data.get("image")
        if not image:
            return image
        # Hard byte cap so a giant file can't exhaust memory/disk.
        if getattr(image, "size", 0) > MAX_PHOTO_UPLOAD_BYTES:
            raise forms.ValidationError("Image is too large (max 15 MB).")
        # Reject decompression bombs before anything gets stored: fully decode
        # under a lowered pixel cap so a small file declaring huge dimensions
        # raises here instead of blowing up RAM later on resize/rotate.
        try:
            from PIL import Image
            Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS_CAP
            image.seek(0)
            with Image.open(image) as img:
                img.load()
        except Exception:
            raise forms.ValidationError("That image couldn't be processed (it may be corrupt or too large).")
        finally:
            try:
                image.seek(0)
            except Exception:
                pass
        return image
