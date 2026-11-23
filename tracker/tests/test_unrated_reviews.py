"""Written reviews without stars: allowed, but only when the submission
confirms it's deliberate (no_rating_ok=1); they never affect averages."""
from django.urls import reverse

from tracker.models import Connection, Item, ItemReview, Location, LocationReview

from .helpers import AppTestCase


class UnratedReviewTests(AppTestCase):
    def setUp(self):
        self.me = self.make_user("me")
        self.loc = Location.objects.create(name="Cafe")
        self.item = Item.objects.create(location=self.loc, name="Latte")
        self.login(self.me)

    def _review(self, **data):
        return self.client.post(reverse("location_review_upsert", args=[self.loc.pk]), data)

    def test_text_without_stars_needs_confirmation(self):
        resp = self._review(rating="", notes="Cozy, slow service")
        self.assertContains(resp, "confirm you want to save the review without one")
        self.assertFalse(LocationReview.objects.exists())

    def test_text_without_stars_saves_once_confirmed(self):
        self._review(rating="", notes="Cozy, slow service", no_rating_ok="1")
        review = LocationReview.objects.get(user=self.me)
        self.assertIsNone(review.rating)
        self.assertEqual(review.notes, "Cozy, slow service")

    def test_nothing_at_all_is_still_rejected(self):
        resp = self._review(rating="", notes="  ", no_rating_ok="1")
        self.assertContains(resp, "Choose a star rating or write a review")
        self.assertFalse(LocationReview.objects.exists())

    def test_stars_alone_still_work(self):
        self._review(rating="4.0", notes="")
        self.assertEqual(str(LocationReview.objects.get(user=self.me).rating), "4.0")

    def test_unrated_reviews_are_left_out_of_averages_and_shown_as_unrated(self):
        other = self.make_user("other")
        LocationReview.objects.create(location=self.loc, user=other, rating="4.0")
        self._review(rating="", notes="Written only", no_rating_ok="1")
        self.assertEqual(self.loc.avg_user_rating, 4.0)
        detail = self.client.get(reverse("location_detail", args=[self.loc.pk]))
        self.assertContains(detail, "No star rating")
        self.assertContains(detail, "average of 1 rating")
        home = self.client.get(reverse("location_list"))
        self.assertEqual(next(w for w in home.context["waypoints"] if w["name"] == "Cafe")["rating"], 4.0)

    def test_dish_review_without_stars(self):
        self._review(rating="3.0")
        url = reverse("item_review_upsert", args=[self.loc.pk, self.item.pk])
        self.client.post(url, {"rating": "", "notes": "Too sweet"})
        self.assertFalse(ItemReview.objects.exists())
        self.client.post(url, {"rating": "", "notes": "Too sweet", "no_rating_ok": "1"})
        self.assertIsNone(ItemReview.objects.get(user=self.me).rating)

    def test_new_dish_with_written_first_review(self):
        self._review(rating="3.0")
        self.client.post(reverse("item_add", args=[self.loc.pk]),
                         {"name": "Scone", "initial_rating": "", "initial_notes": "Dry", "no_rating_ok": "1"})
        review = ItemReview.objects.get(item__name="Scone")
        self.assertIsNone(review.rating)
        self.assertEqual(review.notes, "Dry")

    def test_on_behalf_review_without_stars(self):
        friend = self.make_user("friend")
        lo, hi = sorted([self.me, friend], key=lambda u: u.pk)
        Connection.objects.create(user_low=lo, user_high=hi)
        url = reverse("location_review_on_behalf", args=[self.loc.pk])
        self.client.post(url, {"subject": friend.pk, "rating": "", "notes": "They liked it"})
        self.assertFalse(LocationReview.objects.filter(user=friend).exists())
        self.client.post(url, {"subject": friend.pk, "rating": "", "notes": "They liked it", "no_rating_ok": "1"})
        self.assertIsNone(LocationReview.objects.get(user=friend).rating)
        item_url = reverse("item_review_on_behalf", args=[self.loc.pk, self.item.pk])
        self.client.post(item_url, {"subject": friend.pk, "rating": "", "notes": "Fine", "no_rating_ok": "1"})
        self.assertIsNone(ItemReview.objects.get(user=friend).rating)
