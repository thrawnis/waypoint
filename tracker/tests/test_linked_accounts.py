"""Linked accounts: one-to-one connections that let two users post waypoint/
item reviews on each other's behalf.

The rules that matter here (see tracker/models.py Connection docstring and
tracker/views.py's on_behalf views) are the ones easy to silently break:
- non-transitive — A linked to B and B linked to C never links A to C
- you can add or edit a linked account's review (without needing a review
  of your own first), but never delete theirs — not even indirectly through
  your own review-delete endpoint
- editing never exposes or changes the subject's private dish notes
- submitted_by/subject_seen are stamped correctly so the subject can later
  see who posted on their behalf
"""
from django.urls import reverse

from tracker.models import Connection, ConnectToken, Item, ItemReview, Location, LocationReview
from tracker.tests.helpers import AppTestCase
from tracker.views import linked_account_ids


def connect(a, b):
    low, high = Connection.ordered(a, b)
    Connection.objects.get_or_create(user_low=low, user_high=high)


def connect_token_for(user):
    # Views create this lazily (see _my_connect_token) when a user first
    # visits their linked-accounts page — tests that jump straight to the
    # invite link need to create it themselves.
    token, _ = ConnectToken.objects.get_or_create(user=user)
    return token.token


class NonTransitivityTests(AppTestCase):
    def test_connection_is_not_transitive(self):
        a = self.make_user("a")
        b = self.make_user("b")
        c = self.make_user("c")
        connect(a, b)
        connect(b, c)

        self.assertIn(b.pk, linked_account_ids(a))
        self.assertIn(a.pk, linked_account_ids(b))
        self.assertIn(c.pk, linked_account_ids(b))
        self.assertIn(b.pk, linked_account_ids(c))
        # The actual point of the test: A and C share a mutual connection to
        # B, but are NOT connected to each other.
        self.assertNotIn(c.pk, linked_account_ids(a))
        self.assertNotIn(a.pk, linked_account_ids(c))

    def test_ordering_is_symmetric_regardless_of_who_connects(self):
        a = self.make_user("alpha")
        b = self.make_user("beta")
        connect(a, b)
        connect(b, a)  # same pair, reversed order — must not create a duplicate row
        self.assertEqual(Connection.objects.count(), 1)


class LinkedAccountConnectDisconnectTests(AppTestCase):
    def setUp(self):
        self.a = self.make_user("alice")
        self.b = self.make_user("bob")

    def test_cannot_connect_to_own_invite_link(self):
        self.login(self.a)
        token = connect_token_for(self.a)
        resp = self.client.post(reverse("linked_account_connect", args=[token]))
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(Connection.objects.count(), 0)

    def test_opening_someone_elses_invite_and_approving_connects_them(self):
        self.login(self.b)
        token = connect_token_for(self.a)
        resp = self.client.post(reverse("linked_account_connect", args=[token]))
        self.assertEqual(resp.status_code, 302)
        self.assertIn(self.b.pk, linked_account_ids(self.a))
        self.assertIn(self.a.pk, linked_account_ids(self.b))

    def test_connecting_twice_does_not_duplicate(self):
        connect(self.a, self.b)
        self.login(self.b)
        token = connect_token_for(self.a)
        resp = self.client.post(reverse("linked_account_connect", args=[token]))
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(Connection.objects.count(), 1)

    def test_disconnect_removes_the_connection_from_either_side(self):
        connect(self.a, self.b)
        self.login(self.b)  # b disconnects, even though a wasn't the one who initiated
        resp = self.client.post(reverse("linked_account_disconnect", args=[self.a.pk]))
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(Connection.objects.count(), 0)


class LocationReviewOnBehalfTests(AppTestCase):
    def setUp(self):
        self.a = self.make_user("alice")
        self.b = self.make_user("bob")
        self.stranger = self.make_user("stranger")
        connect(self.a, self.b)
        self.loc = Location.objects.create(name="Cafe", created_by=self.a)

    def test_forbidden_for_a_non_linked_account(self):
        self.login(self.stranger)
        resp = self.client.post(
            reverse("location_review_on_behalf", args=[self.loc.pk]),
            {"subject": self.a.pk, "rating": "4.5", "notes": ""},
        )
        self.assertEqual(resp.status_code, 403)
        self.assertFalse(LocationReview.objects.filter(location=self.loc, user=self.a).exists())

    def test_linked_account_can_add_a_review_for_the_subject(self):
        self.login(self.b)
        resp = self.client.post(
            reverse("location_review_on_behalf", args=[self.loc.pk]),
            {"subject": self.a.pk, "rating": "4.5", "notes": "Great coffee"},
        )
        self.assertEqual(resp.status_code, 200)
        review = LocationReview.objects.get(location=self.loc, user=self.a)
        self.assertEqual(review.submitted_by_id, self.b.pk)
        self.assertFalse(review.subject_seen)   # surfaced to the subject on next login
        self.assertTrue(review.on_behalf)

    def test_can_add_without_a_review_of_your_own(self):
        self.login(self.b)
        self.client.post(
            reverse("location_review_on_behalf", args=[self.loc.pk]),
            {"subject": self.a.pk, "rating": "4.0", "notes": ""},
        )
        self.assertTrue(LocationReview.objects.filter(location=self.loc, user=self.a).exists())
        self.assertFalse(LocationReview.objects.filter(location=self.loc, user=self.b).exists())

    def test_linked_account_can_edit_the_subjects_existing_review(self):
        LocationReview.objects.create(location=self.loc, user=self.a, rating="3.0", notes="meh")
        self.login(self.b)
        form = self.client.get(
            reverse("location_review_on_behalf", args=[self.loc.pk]) + "?subject={}".format(self.a.pk))
        self.assertContains(form, "Editing on behalf of alice")
        self.assertContains(form, "meh")
        resp = self.client.post(
            reverse("location_review_on_behalf", args=[self.loc.pk]),
            {"subject": self.a.pk, "rating": "5.0", "notes": "amazing"},
        )
        self.assertEqual(resp.status_code, 200)
        review = LocationReview.objects.get(location=self.loc, user=self.a)
        self.assertEqual((str(review.rating), review.notes), ("5.0", "amazing"))
        self.assertEqual(review.submitted_by_id, self.b.pk)
        self.assertFalse(review.subject_seen)   # they're told it changed

    def test_stranger_cannot_open_the_edit_form(self):
        LocationReview.objects.create(location=self.loc, user=self.a, rating="3.0", notes="private-ish")
        self.login(self.stranger)
        resp = self.client.get(
            reverse("location_review_on_behalf", args=[self.loc.pk]) + "?subject={}".format(self.a.pk))
        self.assertEqual(resp.status_code, 403)

    def test_subject_rewriting_their_review_clears_the_on_behalf_mark(self):
        LocationReview.objects.create(location=self.loc, user=self.a, rating="3.0",
                                      submitted_by=self.b, subject_seen=False)
        self.login(self.a)
        self.client.post(reverse("location_review_upsert", args=[self.loc.pk]), {"rating": "4.0", "notes": ""})
        review = LocationReview.objects.get(location=self.loc, user=self.a)
        self.assertFalse(review.on_behalf)

    def test_subject_cannot_be_someone_you_are_not_linked_to_even_if_valid_pk(self):
        # b is linked to a, but not to stranger — subject=stranger must be
        # rejected even though stranger is a real user.
        self.login(self.b)
        resp = self.client.post(
            reverse("location_review_on_behalf", args=[self.loc.pk]),
            {"subject": self.stranger.pk, "rating": "4.0", "notes": ""},
        )
        self.assertEqual(resp.status_code, 403)
        self.assertFalse(LocationReview.objects.filter(location=self.loc, user=self.stranger).exists())

    def test_on_behalf_review_can_only_be_deleted_by_the_subject_not_the_submitter(self):
        self.login(self.b)
        self.client.post(
            reverse("location_review_on_behalf", args=[self.loc.pk]),
            {"subject": self.a.pk, "rating": "4.5", "notes": ""},
        )
        # b (who submitted it) tries to delete it via the normal delete
        # endpoint, which is always scoped to request.user — b has no review
        # of their own here, so this 404s rather than deleting a's review.
        resp = self.client.post(
            reverse("location_review_delete", args=[self.loc.pk]), {"reason": "oops"},
        )
        self.assertEqual(resp.status_code, 404)
        self.assertTrue(LocationReview.objects.filter(location=self.loc, user=self.a).exists())


class ItemReviewOnBehalfTests(AppTestCase):
    def setUp(self):
        self.a = self.make_user("alice")
        self.b = self.make_user("bob")
        self.stranger = self.make_user("stranger")
        connect(self.a, self.b)
        self.loc = Location.objects.create(name="Cafe", created_by=self.a)
        self.item = Item.objects.create(location=self.loc, name="Latte")

    def test_forbidden_for_a_non_linked_account(self):
        self.login(self.stranger)
        resp = self.client.post(
            reverse("item_review_on_behalf", args=[self.loc.pk, self.item.pk]),
            {"subject": self.a.pk, "rating": "4.0", "notes": ""},
        )
        self.assertEqual(resp.status_code, 403)

    def test_does_not_require_the_subject_to_have_rated_the_waypoint_first(self):
        # Regression test: this used to require the subject to already have a
        # LocationReview before a dish review could be added on their behalf.
        self.assertFalse(LocationReview.objects.filter(location=self.loc, user=self.a).exists())
        self.login(self.b)
        resp = self.client.post(
            reverse("item_review_on_behalf", args=[self.loc.pk, self.item.pk]),
            {"subject": self.a.pk, "rating": "4.0", "notes": "Good latte"},
        )
        self.assertEqual(resp.status_code, 200)
        review = ItemReview.objects.get(item=self.item, user=self.a)
        self.assertEqual(review.submitted_by_id, self.b.pk)

    def test_linked_account_can_edit_the_subjects_dish_review_keeping_private_notes(self):
        ItemReview.objects.create(item=self.item, user=self.a, rating="2.0", notes="not for me",
                                  private_notes="alice's own aside")
        self.login(self.b)
        form = self.client.get(
            reverse("item_review_on_behalf", args=[self.loc.pk, self.item.pk]) + "?subject={}".format(self.a.pk))
        self.assertContains(form, "Editing on behalf of alice")
        self.assertNotContains(form, "alice's own aside")
        resp = self.client.post(
            reverse("item_review_on_behalf", args=[self.loc.pk, self.item.pk]),
            {"subject": self.a.pk, "rating": "5.0", "notes": "love it",
             "private_notes": "b tries to overwrite this"},
        )
        self.assertEqual(resp.status_code, 200)
        review = ItemReview.objects.get(item=self.item, user=self.a)
        self.assertEqual((str(review.rating), review.notes), ("5.0", "love it"))
        self.assertEqual(review.private_notes, "alice's own aside")
        self.assertEqual(review.submitted_by_id, self.b.pk)

    def test_on_behalf_review_never_carries_private_notes(self):
        self.login(self.b)
        self.client.post(
            reverse("item_review_on_behalf", args=[self.loc.pk, self.item.pk]),
            {"subject": self.a.pk, "rating": "4.0", "notes": "fine",
             "private_notes": "b's snarky private aside"},
        )
        review = ItemReview.objects.get(item=self.item, user=self.a)
        self.assertEqual(review.private_notes, "")
