"""The "Has activity" filter's flag: set for any waypoint someone has recorded
something about, not for ones that were merely saved."""
from django.urls import reverse

from tracker.models import Item, Location, LocationReview, PrivateNote

from .helpers import AppTestCase


class ActivityFlagTests(AppTestCase):
    def setUp(self):
        self.me = self.make_user("me")
        self.other = self.make_user("other")

    def _flags(self):
        self.login(self.me)
        resp = self.client.get(reverse("location_list"))
        return {w["name"]: w["active"] for w in resp.context["waypoints"]}

    def test_flags(self):
        Location.objects.create(name="Bare")
        rated = Location.objects.create(name="Reviewed by someone else")
        LocationReview.objects.create(location=rated, user=self.other, rating=4)
        dish = Location.objects.create(name="Has a dish")
        Item.objects.create(location=dish, name="Fries")
        Location.objects.create(name="Public notes", public_notes="Great patio")
        Location.objects.create(name="GF info", gluten_free=Location.GF_OPTIONS)
        mine = Location.objects.create(name="My private note")
        PrivateNote.objects.create(location=mine, user=self.me, text="secret")
        theirs = Location.objects.create(name="Their private note", created_by=self.me)
        PrivateNote.objects.create(location=theirs, user=self.other, text="secret")
        Location.objects.create(name="Whitespace notes", public_notes="   ")

        self.assertEqual(self._flags(), {
            "Bare": False,
            "Reviewed by someone else": True,
            "Has a dish": True,
            "Public notes": True,
            "GF info": True,
            "My private note": True,
            "Their private note": False,
            "Whitespace notes": False,
        })

    def test_card_carries_flag_and_menu_links_to_filtered_list(self):
        Location.objects.create(name="Noted", public_notes="x")
        self.login(self.me)
        resp = self.client.get(reverse("location_list"))
        self.assertContains(resp, 'data-active="1"')
        self.assertContains(resp, 'id="active-filter"')
        self.assertContains(resp, "?panel=active")
