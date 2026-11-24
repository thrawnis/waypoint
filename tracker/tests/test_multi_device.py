"""Several devices can be signed in to the same account at once, and active
devices stay signed in."""
import json
import time
from datetime import timedelta

from django.conf import settings
from django.contrib.sessions.models import Session
from django.test import Client
from django.urls import reverse
from django.utils import timezone

from .helpers import TEST_PASSWORD, AppTestCase
from .test_webauthn import FakeAuthenticator


class MultiDeviceTests(AppTestCase):
    def setUp(self):
        self.user = self.make_user("multi")
        self.phone, self.laptop, self.tablet = Client(), Client(), Client()

    def _password_login(self, client):
        resp = client.post(reverse("login"), {"username": "multi", "password": TEST_PASSWORD})
        self.assertEqual(resp.status_code, 302)

    def _signed_in(self, client):
        return client.get(reverse("location_list")).status_code == 200

    def test_signing_in_on_another_device_keeps_the_first_signed_in(self):
        self._password_login(self.phone)
        self._password_login(self.laptop)
        self._password_login(self.tablet)
        self.assertTrue(all(self._signed_in(c) for c in (self.phone, self.laptop, self.tablet)))
        self.assertEqual(Session.objects.count(), 3)

    def test_signing_out_on_one_device_leaves_the_others_signed_in(self):
        self._password_login(self.phone)
        self._password_login(self.laptop)
        self.laptop.post(reverse("logout"))
        self.assertFalse(self._signed_in(self.laptop))
        self.assertTrue(self._signed_in(self.phone))

    def test_passkey_sign_in_on_a_second_device_keeps_the_first(self):
        self._password_login(self.phone)
        key = FakeAuthenticator()
        opts = json.loads(self.phone.post(reverse("passkey_register_options")).content)
        cred = key.create(opts["challenge"], "testserver", "http://testserver")
        self.phone.post(reverse("passkey_register_verify"), data=json.dumps(cred), content_type="application/json")

        opts = json.loads(self.laptop.post(reverse("passkey_login_options")).content)
        assertion = key.get(opts["challenge"], "testserver", "http://testserver")
        resp = self.laptop.post(reverse("passkey_login_verify"), data=json.dumps(assertion),
                                content_type="application/json")
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertTrue(self._signed_in(self.laptop))
        self.assertTrue(self._signed_in(self.phone))


class SessionRefreshTests(AppTestCase):
    def setUp(self):
        self.user = self.make_user("active")
        self.login(self.user)
        self.client.get(reverse("location_list"))   # first request stamps the session
        self.key = self.client.session.session_key

    def _age_session(self, days_since_refresh):
        session = self.client.session
        session["_refreshed_at"] = int(time.time()) - days_since_refresh * 86400
        session.save()
        Session.objects.filter(session_key=self.key).update(
            expire_date=timezone.now() + timedelta(seconds=settings.SESSION_COOKIE_AGE) - timedelta(days=days_since_refresh))

    def test_a_device_in_use_keeps_getting_its_session_extended(self):
        self._age_session(days_since_refresh=10)     # 4 days left
        resp = self.client.get(reverse("location_list"))
        self.assertEqual(resp.status_code, 200)
        expires = Session.objects.get(session_key=self.key).expire_date
        self.assertGreater(expires, timezone.now() + timedelta(days=13))
        self.assertIn(settings.SESSION_COOKIE_NAME, resp.cookies)   # cookie lifetime renewed too

    def test_no_write_while_the_session_is_still_fresh(self):
        self._age_session(days_since_refresh=1)
        before = Session.objects.get(session_key=self.key).expire_date
        resp = self.client.get(reverse("location_list"))
        self.assertEqual(Session.objects.get(session_key=self.key).expire_date, before)
        self.assertNotIn(settings.SESSION_COOKIE_NAME, resp.cookies)
