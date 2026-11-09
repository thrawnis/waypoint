"""Passkey (WebAuthn) support: a fake software authenticator exercises the
real registration/authentication endpoints end-to-end (no browser needed),
plus the "either method satisfies MFA" business rules around it."""
import base64
import hashlib
import json

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from django.urls import reverse

from tracker.models import TOTPDevice, WebAuthnCredential

from .helpers import TEST_PASSWORD, AppTestCase


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class FakeAuthenticator:
    """A minimal ES256 / "none"-attestation software authenticator — enough
    to produce real, verifiable WebAuthn registration and authentication
    responses without a browser or hardware."""

    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = b"test-credential-0001"
        self.sign_count = 0

    def _public_key_cose(self):
        numbers = self.private_key.public_key().public_numbers()
        return cbor2.dumps({
            1: 2, 3: -7, -1: 1,                       # kty=EC2, alg=ES256, crv=P-256
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        })

    def _auth_data(self, rp_id, attested):
        self.sign_count += 1
        flags = 0x05 | (0x40 if attested else 0)       # user present + verified [+ attested cred data]
        data = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + self.sign_count.to_bytes(4, "big")
        if attested:
            data += b"\x00" * 16 + len(self.credential_id).to_bytes(2, "big") + self.credential_id
            data += self._public_key_cose()
        return data

    def create(self, challenge_b64, rp_id, origin):
        client_data = json.dumps(
            {"type": "webauthn.create", "challenge": challenge_b64, "origin": origin}
        ).encode()
        auth_data = self._auth_data(rp_id, attested=True)
        attestation_object = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {
            "id": _b64url(self.credential_id),
            "rawId": _b64url(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": _b64url(client_data),
                "attestationObject": _b64url(attestation_object),
            },
        }

    def get(self, challenge_b64, rp_id, origin):
        client_data = json.dumps(
            {"type": "webauthn.get", "challenge": challenge_b64, "origin": origin}
        ).encode()
        auth_data = self._auth_data(rp_id, attested=False)
        signature = self.private_key.sign(
            auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256())
        )
        return {
            "id": _b64url(self.credential_id),
            "rawId": _b64url(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": _b64url(client_data),
                "authenticatorData": _b64url(auth_data),
                "signature": _b64url(signature),
                "userHandle": None,
            },
        }


class PasskeyFlowTests(AppTestCase):
    def test_register_then_login_with_passkey(self):
        user = self.make_user("alice")
        self.login(user)
        authenticator = FakeAuthenticator()

        options = json.loads(self.client.post(reverse("passkey_register_options")).content)
        credential = authenticator.create(options["challenge"], "testserver", "http://testserver")
        credential["_name"] = "Test Device"
        verify = self.client.post(
            reverse("passkey_register_verify"), data=json.dumps(credential), content_type="application/json",
        )
        self.assertEqual(verify.status_code, 200, verify.content)
        self.assertTrue(WebAuthnCredential.objects.filter(user=user, name="Test Device").exists())

        self.client.logout()
        login_res = self.client.post(
            reverse("login"), {"username": user.username, "password": TEST_PASSWORD}
        )
        self.assertRedirects(login_res, reverse("two_factor_verify"))

        auth_options = json.loads(self.client.post(reverse("passkey_auth_options")).content)
        assertion = authenticator.get(auth_options["challenge"], "testserver", "http://testserver")
        auth_verify = self.client.post(
            reverse("passkey_auth_verify"), data=json.dumps(assertion), content_type="application/json",
        )
        self.assertEqual(auth_verify.status_code, 200, auth_verify.content)
        self.assertEqual(self.client.get(reverse("location_list")).status_code, 200)

    def test_passwordless_login_with_only_a_passkey(self):
        """No username/password ever submitted — the credential alone
        identifies and logs in the user."""
        user = self.make_user("carol")
        self.login(user)
        authenticator = FakeAuthenticator()
        options = json.loads(self.client.post(reverse("passkey_register_options")).content)
        credential = authenticator.create(options["challenge"], "testserver", "http://testserver")
        self.client.post(
            reverse("passkey_register_verify"), data=json.dumps(credential), content_type="application/json",
        )
        self.client.logout()

        login_options = json.loads(self.client.post(reverse("passkey_login_options")).content)
        assertion = authenticator.get(login_options["challenge"], "testserver", "http://testserver")
        verify = self.client.post(
            reverse("passkey_login_verify"), data=json.dumps(assertion), content_type="application/json",
        )
        self.assertEqual(verify.status_code, 200, verify.content)
        self.assertEqual(self.client.get(reverse("location_list")).status_code, 200)

    def test_passwordless_login_rejects_unknown_credential(self):
        authenticator = FakeAuthenticator()
        self.client.post(reverse("passkey_login_options"))
        bogus = {"id": "x", "rawId": _b64url(b"no-such-credential"),
                 "type": "public-key", "response": {}}
        resp = self.client.post(
            reverse("passkey_login_verify"), data=json.dumps(bogus), content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)

    def test_wrong_credential_id_is_rejected(self):
        user = self.make_user("bob")
        WebAuthnCredential.objects.create(user=user, credential_id=b"real-one", public_key=b"x")
        session = self.client.session
        session["pre_2fa_user"] = user.pk
        session.save()
        self.client.post(reverse("passkey_auth_options"))
        bogus = {"id": "x", "rawId": _b64url(b"not-the-real-credential"),
                 "type": "public-key", "response": {}}
        resp = self.client.post(
            reverse("passkey_auth_verify"), data=json.dumps(bogus), content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)


class MfaEitherOrTests(AppTestCase):
    """Passkey and TOTP are alternatives — one is enough, and removing one
    is only blocked (for admins) when it would leave zero MFA methods."""

    def test_staff_with_only_passkey_is_not_forced_into_setup(self):
        user = self.make_user("admin1", is_staff=True)
        TOTPDevice.objects.filter(user=user).delete()
        WebAuthnCredential.objects.create(user=user, credential_id=b"cred-1", public_key=b"x")
        self.login(user)
        self.assertEqual(self.client.get(reverse("location_list")).status_code, 200)

    def test_staff_with_neither_method_is_forced_into_setup(self):
        user = self.make_user("admin2", is_staff=True)
        TOTPDevice.objects.filter(user=user).delete()
        self.login(user)
        resp = self.client.get(reverse("location_list"))
        self.assertRedirects(resp, reverse("two_factor_setup"))

    def test_cannot_disable_totp_as_staffs_last_mfa_method(self):
        user = self.make_user("admin3", is_staff=True)   # make_user gives a confirmed TOTPDevice
        self.login(user)
        self.client.post(reverse("two_factor_disable"))
        self.assertTrue(TOTPDevice.objects.filter(user=user, confirmed=True).exists())

    def test_can_disable_totp_when_a_passkey_also_exists(self):
        user = self.make_user("admin4", is_staff=True)
        WebAuthnCredential.objects.create(user=user, credential_id=b"cred-2", public_key=b"x")
        self.login(user)
        self.client.post(reverse("two_factor_disable"))
        self.assertFalse(TOTPDevice.objects.filter(user=user).exists())

    def test_cannot_delete_staffs_last_passkey_with_no_totp(self):
        user = self.make_user("admin5", is_staff=True)
        TOTPDevice.objects.filter(user=user).delete()
        cred = WebAuthnCredential.objects.create(user=user, credential_id=b"cred-3", public_key=b"x")
        self.login(user)
        self.client.post(reverse("passkey_delete", args=[cred.pk]))
        self.assertTrue(WebAuthnCredential.objects.filter(pk=cred.pk).exists())

    def test_can_delete_a_passkey_when_totp_also_enabled(self):
        user = self.make_user("admin6", is_staff=True)   # confirmed TOTPDevice from make_user
        cred = WebAuthnCredential.objects.create(user=user, credential_id=b"cred-4", public_key=b"x")
        self.login(user)
        self.client.post(reverse("passkey_delete", args=[cred.pk]))
        self.assertFalse(WebAuthnCredential.objects.filter(pk=cred.pk).exists())

    def test_setup_chooser_redirects_away_once_a_method_exists(self):
        user = self.make_user("regular1")
        WebAuthnCredential.objects.create(user=user, credential_id=b"cred-5", public_key=b"x")
        self.login(user)
        self.assertRedirects(self.client.get(reverse("two_factor_setup")), reverse("two_factor_settings"))

    def test_setup_chooser_offers_both_methods_with_none_set_up(self):
        user = self.make_user("regular2")
        self.login(user)
        resp = self.client.get(reverse("two_factor_setup"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Set up a passkey")
        self.assertContains(resp, "Set up an authenticator app")
