"""Private notes: each user's own note on a place, visible only to them —
not to other users, superusers or admins, and never in the audit log."""
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase
from django.urls import reverse

from tracker.models import AuditLog, Location, PrivateNote

from .helpers import AppTestCase

SECRET = "door code 4417, ask for Sam"


class PrivateNoteTests(AppTestCase):
    def setUp(self):
        self.alice = self.make_user("alice")
        self.place = Location.objects.create(name="Taqueria", created_by=self.make_user("creator"))

    def _save(self, user, text):
        self.login(user)
        return self.client.post(reverse("private_note_save", args=[self.place.pk]), {"text": text})

    def test_any_user_can_note_a_place_they_did_not_create(self):
        resp = self._save(self.alice, SECRET)
        self.assertContains(resp, SECRET)
        self.assertEqual(PrivateNote.objects.get(user=self.alice, location=self.place).text, SECRET)
        detail = self.client.get(reverse("location_detail", args=[self.place.pk]))
        self.assertContains(detail, SECRET)

    def test_nobody_else_sees_it_not_even_admins_or_superusers(self):
        self._save(self.alice, SECRET)
        for viewer in (
            self.make_user("bob"),
            self.make_user("mod", superuser_role=True),
            self.make_user("boss", is_staff=True),
            self.place.created_by,
        ):
            self.login(viewer)
            detail = self.client.get(reverse("location_detail", args=[self.place.pk]))
            self.assertEqual(detail.status_code, 200)
            self.assertNotContains(detail, SECRET, msg_prefix=viewer.username)
            edit = self.client.get(reverse("location_edit", args=[self.place.pk]))
            if edit.status_code == 200:   # only those allowed to edit the place
                self.assertNotContains(edit, SECRET, msg_prefix=viewer.username)

    def test_saving_blank_deletes_it(self):
        self._save(self.alice, SECRET)
        self._save(self.alice, "   ")
        self.assertFalse(PrivateNote.objects.filter(user=self.alice).exists())

    def test_someone_else_editing_the_place_keeps_my_note(self):
        """The old single field was wiped whenever anyone else saved the edit form."""
        creator = self.place.created_by
        PrivateNote.objects.create(location=self.place, user=creator, text=SECRET)
        admin = self.make_user("admin", is_staff=True)
        self.login(admin)
        self.client.post(reverse("location_edit", args=[self.place.pk]), {
            "name": "Taqueria (renamed)", "gluten_free": "",
        })
        self.place.refresh_from_db()
        self.assertEqual(self.place.name, "Taqueria (renamed)")
        self.assertEqual(PrivateNote.objects.get(user=creator).text, SECRET)
        self.assertFalse(PrivateNote.objects.filter(user=admin).exists())

    def test_edit_form_saves_my_own_note(self):
        creator = self.place.created_by
        self.login(creator)
        self.client.post(reverse("location_edit", args=[self.place.pk]), {
            "name": "Taqueria", "gluten_free": "", "my_private_note": SECRET,
        })
        self.assertEqual(PrivateNote.objects.get(user=creator).text, SECRET)

    def test_never_written_to_the_audit_log(self):
        creator = self.place.created_by
        self.login(creator)
        self.client.post(reverse("location_edit", args=[self.place.pk]), {
            "name": "Taqueria", "gluten_free": "", "my_private_note": SECRET,
        })
        self._save(self.alice, SECRET)
        self.assertFalse(AuditLog.objects.filter(detail__contains="door code").exists())

    def test_requires_login_and_post(self):
        url = reverse("private_note_save", args=[self.place.pk])
        self.assertEqual(self.client.post(url, {"text": SECRET}).status_code, 302)
        self.login(self.alice)
        self.assertEqual(self.client.get(url).status_code, 405)
        self.assertFalse(PrivateNote.objects.exists())


class MigrationTests(TransactionTestCase):
    """The old single per-place field becomes its creator's own note."""
    BEFORE = [("tracker", "0029_unverify_unconfirmed_emails")]
    AFTER = [("tracker", "0030_private_notes_per_user")]

    def test_old_notes_move_to_their_creator(self):
        executor = MigrationExecutor(connection)
        executor.migrate(self.BEFORE)
        old = executor.loader.project_state(self.BEFORE).apps
        creator = old.get_model("auth", "User").objects.create(username="creator")
        Loc = old.get_model("tracker", "Location")
        Loc.objects.create(name="Noted", private_notes="  " + SECRET + " ", created_by=creator)
        Loc.objects.create(name="Blank", private_notes="   ", created_by=creator)
        Loc.objects.create(name="Orphaned", private_notes="no owner left")

        executor = MigrationExecutor(connection)
        executor.migrate(self.AFTER)
        new = executor.loader.project_state(self.AFTER).apps
        notes = list(new.get_model("tracker", "PrivateNote").objects.values_list(
            "location__name", "user__username", "text"))
        self.assertEqual(notes, [("Noted", "creator", SECRET)])
