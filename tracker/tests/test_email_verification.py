"""Required email verification: with it on, no account (new or pre-existing)
can use the app until it confirms its address."""
import importlib
import time
from datetime import timedelta

from django.apps import apps
from django.core import mail, signing
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone

from tracker.models import EmailVerification

from .helpers import AppTestCase


@override_settings(
    REQUIRE_EMAIL_VERIFICATION=True,
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
)
class RequiredVerificationTests(AppTestCase):
    def _link_from_outbox(self):
        body = mail.outbox[-1].body
        return next(line for line in body.splitlines() if "token=" in line).strip()

    def test_existing_unverified_account_is_gated_and_auto_sent_a_link(self):
        user = self.make_user("legacy")
        self.login(user)
        self.assertRedirects(self.client.get(reverse("location_list")), reverse("verify_email"))
        resp = self.client.get(reverse("verify_email"))
        self.assertContains(resp, "We sent a verification link")
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, [user.email])

        # Revisiting the page doesn't send another one.
        self.client.get(reverse("verify_email"))
        self.assertEqual(len(mail.outbox), 1)

    def test_confirming_the_link_unlocks_the_app(self):
        user = self.make_user("confirmer")
        self.login(user)
        self.client.get(reverse("verify_email"))
        self.client.get(self._link_from_outbox())
        self.assertTrue(EmailVerification.objects.get(user=user).verified)
        self.assertEqual(self.client.get(reverse("location_list")).status_code, 200)

    def test_passkey_only_login_is_gated_too(self):
        """Signing in without a password doesn't skip verification."""
        user = self.make_user("passkeyuser")
        self.client.force_login(user)
        self.assertRedirects(self.client.get(reverse("location_list")), reverse("verify_email"))

    def test_changing_email_on_verify_page_requires_reverifying(self):
        user = self.make_user("mover")
        EmailVerification.objects.create(user=user, verified=True, verified_at=timezone.now())
        self.login(user)
        self.assertEqual(self.client.get(reverse("location_list")).status_code, 200)

        self.client.post(reverse("verify_email_resend"), {"email": "new-address@example.com"})
        user.refresh_from_db()
        self.assertEqual(user.email, "new-address@example.com")
        self.assertFalse(EmailVerification.objects.get(user=user).verified)
        self.assertRedirects(self.client.get(reverse("location_list")), reverse("verify_email"))

    def test_old_link_stops_working_after_email_change(self):
        user = self.make_user("relinker")
        old_token = signing.dumps({"uid": user.pk, "email": user.email}, salt="wp-email-verify")
        user.email = "other@example.com"
        user.save()
        self.client.get(reverse("verify_email_confirm") + "?token=" + old_token)
        self.assertFalse(EmailVerification.objects.filter(user=user, verified=True).exists())

    def test_invalid_email_is_rejected(self):
        user = self.make_user("typo")
        self.login(user)
        self.client.post(reverse("verify_email_resend"), {"email": "not-an-email"})
        user.refresh_from_db()
        self.assertEqual(user.email, "typo@example.com")

    def test_resend_has_a_cooldown(self):
        user = self.make_user("spammer")
        self.login(user)
        self.client.get(reverse("verify_email"))          # auto-send
        self.client.post(reverse("verify_email_resend"))  # too soon
        self.assertEqual(len(mail.outbox), 1)

        EmailVerification.objects.filter(user=user).update(
            last_sent_at=timezone.now() - timedelta(minutes=5)
        )
        self.client.post(reverse("verify_email_resend"))
        self.assertEqual(len(mail.outbox), 2)


class VerificationOffTests(AppTestCase):
    def test_signup_without_verification_is_not_recorded_as_verified(self):
        """So the account still has to verify if SMTP is switched on later."""
        from tracker import captcha
        session = self.client.session
        session[captcha.SESSION_ANSWER] = "ABCDE"
        session[captcha.SESSION_TIME] = int(time.time())
        session.save()
        self.client.post(reverse("register"), {
            "username": "newbie", "email": "newbie@example.com",
            "password1": "correct horse battery staple 1",
            "password2": "correct horse battery staple 1",
            "captcha": "ABCDE", "agree_terms": "on",
        })
        from django.contrib.auth.models import User
        user = User.objects.get(username="newbie")
        self.assertFalse(EmailVerification.objects.filter(user=user, verified=True).exists())


class UnverifyMigrationTests(AppTestCase):
    def test_auto_marked_accounts_are_reset_but_real_confirmations_kept(self):
        fake = self.make_user("autoflagged")
        real = self.make_user("reallyconfirmed")
        EmailVerification.objects.create(user=fake, verified=True)
        EmailVerification.objects.create(user=real, verified=True, verified_at=timezone.now())

        migration = importlib.import_module("tracker.migrations.0029_unverify_unconfirmed_emails")
        migration.unverify_unconfirmed(apps, None)

        self.assertFalse(EmailVerification.objects.get(user=fake).verified)
        self.assertTrue(EmailVerification.objects.get(user=real).verified)


@override_settings(
    REQUIRE_EMAIL_VERIFICATION=True,
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
)
class PwaEndpointTests(AppTestCase):
    """The service worker and offline page are fetched by the browser itself,
    so the onboarding gates (e.g. email verification) must never redirect them."""

    def test_service_worker_served_from_root_for_gated_user(self):
        self.login(self.make_user("unverified"))
        resp = self.client.get("/sw.js")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Content-Type"], "application/javascript")
        self.assertEqual(resp["Cache-Control"], "no-cache")
        self.assertContains(resp, "/offline/")

    def test_offline_page_is_public(self):
        resp = self.client.get("/offline/")
        self.assertContains(resp, "You're offline")
